package com.qubi.plugins.snmp;// … imports idénticos a tu versión anterior …

import com.qubi.core.model.*;
import com.qubi.plugins.snmp.mib.MibEnricher;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.Snmp;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public class SnmpTrapDriver implements CommandResponder {

    // --- Config
    private final int port;
    private final String pluginId;

    private final int queueCapacity;
    private final int workerThreads;
    public enum OverflowPolicy { BLOCK, DROP_NEWEST }
    private final OverflowPolicy overflowPolicy;
    private final long offerTimeoutMillis;
    private final int udpReceiveBufferBytes;
    private final int maxInboundMessageSize; // IMPORTANT: tamaño del datagrama

    // --- Runtime
    private volatile Consumer<NormalizedEvent> listener = e -> {};
    private volatile MibEnricher mibEnricher;

    // TIPAMOS AL TRANSPORTE REAL (para poder llamar a sus setters)
    private DefaultUdpTransportMapping transport;
    private Snmp snmp;

    private final BlockingQueue<RawTrap> queue;
    private ExecutorService workersPool;

    private final AtomicLong enqueued  = new AtomicLong();
    private final AtomicLong dropped   = new AtomicLong();
    private final AtomicLong processed = new AtomicLong();

    private List<SnmpV3User> v3Users;
    private boolean enableV3 = false;

    // --- DTO liviano
    private static final class RawTrap {
        final String srcIp; final int srcPort; final int pduType; final int approxBytes;
        final List<Map.Entry<String,String>> varbinds;
        RawTrap(String ip, int port, int t, int b, List<Map.Entry<String,String>> v){ this.srcIp=ip; this.srcPort=port; this.pduType=t; this.approxBytes=b; this.varbinds=v; }
    }

    // --- Ctors
    public SnmpTrapDriver(int port) { this(port, "snmp4j-trap"); }

    public SnmpTrapDriver(int port, String pluginId) {
        this(port, pluginId,
                65_536,
                Math.max(2, Runtime.getRuntime().availableProcessors()),
                OverflowPolicy.BLOCK, 2, TimeUnit.MILLISECONDS,
                128 * 1024 * 1024,   // udpReceiveBufferBytes solicitado
                64 * 1024);          // maxInboundMessageSize (64K)
    }

    public SnmpTrapDriver(
            int port,
            String pluginId,
            int queueCapacity,
            int workerThreads,
            OverflowPolicy overflowPolicy,
            long offerTimeout,
            TimeUnit offerTimeoutUnit,
            int udpReceiveBufferBytes,
            int maxInboundMessageSize
    ) {
        this.port = port;
        this.pluginId = pluginId;
        this.queueCapacity = queueCapacity;
        this.workerThreads = workerThreads;
        this.overflowPolicy = overflowPolicy;
        this.offerTimeoutMillis = offerTimeoutUnit.toMillis(offerTimeout);
        this.udpReceiveBufferBytes = udpReceiveBufferBytes;
        this.maxInboundMessageSize = maxInboundMessageSize;
        this.queue = new ArrayBlockingQueue<>(queueCapacity);
    }

    public SnmpTrapDriver(int port, String pluginId, List<SnmpV3User> v3Users) {
        this(port, pluginId);
        setV3Users(v3Users);
    }

    // --- Setters
    public SnmpTrapDriver setListener(Consumer<NormalizedEvent> l) { this.listener = (l!=null)?l:(e->{}); return this; }
    public SnmpTrapDriver setMibEnricher(MibEnricher enricher) { this.mibEnricher = enricher; return this; }
    public SnmpTrapDriver setV3Users(List<SnmpV3User> users) { this.v3Users = users; this.enableV3 = users!=null && !users.isEmpty(); return this; }

    // --- Lifecycle
    public void start() throws Exception {
        UdpAddress addr = new UdpAddress("0.0.0.0/" + port);

        // ⚠️ Usa el ctor con reuseAddress=true (tu decompilado lo muestra)
        // DefaultUdpTransportMapping(UdpAddress udpAddress, boolean reuseAddress)
        transport = new DefaultUdpTransportMapping(addr, /*reuseAddress=*/true);

        // Pide buffers/granularidad antes de listen()
        transport.setReceiveBufferSize(udpReceiveBufferBytes);
        transport.setMaxInboundMessageSize(maxInboundMessageSize);
        transport.setSocketTimeout(0); // non-blocking en hilo propio

        snmp = new Snmp(transport);
        if (enableV3) configureSnmpV3Security();

        snmp.addCommandResponder(this);
        snmp.listen(); // el socket se abre acá; el ListenThread setea el RCVBUF efectivo

        log("[start] binding udp/%d @ %s workers=%d qCap=%d overflow=%s askRCVBUF=%dKB maxIn=%d",
                port, String.valueOf(transport.getListenAddress()),
                workerThreads, queueCapacity, overflowPolicy,
                udpReceiveBufferBytes/1024, maxInboundMessageSize);

        workersPool = Executors.newFixedThreadPool(workerThreads, r -> {
            Thread t = new Thread(r, "snmp-workers-" + pluginId);
            t.setDaemon(true);
            return t;
        });
        for (int i = 0; i < workerThreads; i++) workersPool.submit(this::workerLoop);
    }

    public void stop() {
        try { if (snmp != null) snmp.close(); } catch (Exception ignored) {}
        try { if (transport != null) transport.close(); } catch (Exception ignored) {}
        if (workersPool != null) workersPool.shutdownNow();
        log("[stop] processed=%d enqueued=%d dropped=%d", processed.get(), enqueued.get(), dropped.get());
    }

    // --- Receiver → encola
    @Override public void processPdu(CommandResponderEvent e) {
        try {
            if (e == null || e.getPDU() == null || e.getPeerAddress() == null) return;
            UdpAddress peer = (UdpAddress) e.getPeerAddress();

            List<Map.Entry<String,String>> vbs = new ArrayList<>(Math.max(4,
                    e.getPDU().getVariableBindings() != null ? e.getPDU().getVariableBindings().size() : 0));
            if (e.getPDU().getVariableBindings() != null) {
                for (VariableBinding vb : e.getPDU().getVariableBindings()) {
                    if (vb != null && vb.getOid()!=null && vb.getVariable()!=null) {
                        vbs.add(Map.entry(vb.getOid().toDottedString(), vb.getVariable().toString()));
                    }
                }
            }

            RawTrap raw = new RawTrap(
                    peer.getInetAddress().getHostAddress(),
                    peer.getPort(),
                    e.getPDU().getType(),
                    e.getPDU().toArray().length,
                    vbs
            );

            boolean ok = (overflowPolicy == OverflowPolicy.BLOCK)
                    ? queue.offer(raw, offerTimeoutMillis, TimeUnit.MILLISECONDS)
                    : queue.offer(raw);

            if (ok) {
                enqueued.incrementAndGet();
                log("[received] SNMP trap from %s:%d (PDU type: %d, %d varbinds, %d bytes) - enqueued for processing", 
                    raw.srcIp, raw.srcPort, raw.pduType, raw.varbinds.size(), raw.approxBytes);
            } else {
                dropped.incrementAndGet();
                if (dropped.get() % 1000 == 1)
                    log("[drop] queue full cap=%d totalDropped=%d", queueCapacity, dropped.get());
            }
        } catch (Throwable ex) {
            log("[error] processPdu %s", ex.toString());
        }
    }

    // --- Workers
    private void workerLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                RawTrap raw = queue.poll(250, TimeUnit.MILLISECONDS);
                if (raw == null) continue;

                Map<String,Object> varbinds = new LinkedHashMap<>(Math.max(4, raw.varbinds.size()));
                for (Map.Entry<String,String> e : raw.varbinds) varbinds.put(e.getKey(), e.getValue());

                MibEnricher enricher = this.mibEnricher;
                if (enricher != null && !varbinds.isEmpty()) {
                    try { varbinds = enricher.enrich(varbinds); } catch (Exception ignore) {}
                }

                Object trapOid = varbinds.get("1.3.6.1.6.3.1.1.4.1.0");
                if (trapOid != null && !varbinds.containsKey("snmpTrapOID")) varbinds.put("snmpTrapOID", trapOid.toString());

                Map<String,Object> attrs = new LinkedHashMap<>(varbinds.size() + 2);
                Map<String,Object> snmpNs = new LinkedHashMap<>(1);
                snmpNs.put("varbinds", new LinkedHashMap<>(varbinds));
                attrs.put("snmp", snmpNs);
                
                // Add snmpTrapOID at the top level for easy access
                if (trapOid != null) {
                    attrs.put("snmpTrapOID", trapOid.toString());
                }

                NormalizedEvent evt = NormalizedEvent.builder()
                        .ts(Instant.now())
                        .protocol(Protocol.SNMP_TRAP)
                        .kind(EventKind.TRAP)
                        .source(new Source(raw.srcIp, raw.srcPort, null, Transport.UDP))
                        .pluginId(pluginId)
                        .tags(Map.of("pduType", String.valueOf(raw.pduType)))
                        .attributes(attrs)
                        .bytes(raw.approxBytes)
                        .build();

                log("[processing] Normalized event from %s:%d - sending to listener", raw.srcIp, raw.srcPort);
                listener.accept(evt);
                processed.incrementAndGet();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (Throwable t) {
                log("[worker-error] %s", t.toString());
            }
        }
    }

    // --- SNMPv3
    private void configureSnmpV3Security() {
        SecurityProtocols sp = SecurityProtocols.getInstance();
        sp.addDefaultProtocols();
        sp.addAuthenticationProtocol(new AuthMD5());
        sp.addAuthenticationProtocol(new AuthSHA());
        sp.addPrivacyProtocol(new PrivDES());
        sp.addPrivacyProtocol(new PrivAES128());

        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

        if (v3Users != null) {
            for (SnmpV3User u : v3Users) {
                UsmUser usmUser = new UsmUser(
                        new OctetString(u.getUsername()),
                        u.getAuthProtocol(),
                        u.getAuthPassphrase() != null ? new OctetString(u.getAuthPassphrase()) : null,
                        u.getPrivProtocol(),
                        u.getPrivPassphrase() != null ? new OctetString(u.getPrivPassphrase()) : null
                );
                snmp.getUSM().addUser(new OctetString(u.getUsername()), usmUser);
            }
        }
    }

    // --- Util
    private static void log(String fmt, Object... args) {
        System.out.println(String.format(Locale.ROOT, fmt, args));
    }

    // --- DTO helper v3 (igual al anterior)
    public static class SnmpV3User {
        private final String username; private final OID authProtocol; private final String authPassphrase; private final OID privProtocol; private final String privPassphrase;
        public SnmpV3User(String u){ this(u,null,null,null,null); }
        public SnmpV3User(String u, OID a, String ap){ this(u,a,ap,null,null); }
        public SnmpV3User(String u, OID a, String ap, OID p, String pp){ this.username=u; this.authProtocol=a; this.authPassphrase=ap; this.privProtocol=p; this.privPassphrase=pp; }
        public String getUsername(){ return username; } public OID getAuthProtocol(){ return authProtocol; } public String getAuthPassphrase(){ return authPassphrase; }
        public OID getPrivProtocol(){ return privProtocol; } public String getPrivPassphrase(){ return privPassphrase; }
        public static SnmpV3User withMD5Auth(String u, String p){ return new SnmpV3User(u, AuthMD5.ID, p); }
        public static SnmpV3User withSHA1Auth(String u, String p){ return new SnmpV3User(u, AuthSHA.ID, p); }
        public static SnmpV3User withMD5AuthDESPriv(String u, String ap, String pp){ return new SnmpV3User(u, AuthMD5.ID, ap, PrivDES.ID, pp); }
        public static SnmpV3User withSHA1AuthDESPriv(String u, String ap, String pp){ return new SnmpV3User(u, AuthSHA.ID, ap, PrivDES.ID, pp); }
    }

    // --- Métricas
    public long getEnqueued(){ return enqueued.get(); }
    public long getDropped(){ return dropped.get(); }
    public long getProcessed(){ return processed.get(); }
}
