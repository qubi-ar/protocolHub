package com.qubi.plugins.snmp;

import com.qubi.core.model.*;
import com.qubi.plugins.snmp.mib.MibEnricher;
import org.snmp4j.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

public class SnmpTrapDriver implements CommandResponder {
    private final int port;
    private final String pluginId;
    private Consumer<NormalizedEvent> listener = e -> {};
    private TransportMapping<UdpAddress> transport;
    private Snmp snmp;

    // opcional: enriquecimiento por MIB
    private MibEnricher mibEnricher;

    public SnmpTrapDriver(int port) { this(port, "snmp4j-trap"); }
    public SnmpTrapDriver(int port, String pluginId) {
        this.port = port;
        this.pluginId = pluginId;
    }

    public void setListener(Consumer<NormalizedEvent> l) { this.listener = (l != null) ? l : e -> {}; }
    public void setMibEnricher(MibEnricher enricher) { this.mibEnricher = enricher; }

    public void start() throws Exception {
        UdpAddress addr = new UdpAddress("0.0.0.0/" + port);
        transport = new DefaultUdpTransportMapping(addr);
        snmp = new Snmp(transport);
        snmp.addCommandResponder(this);
        snmp.listen();
    }

    public void stop() {
        try { if (snmp != null) snmp.close(); } catch (Exception ignored) {}
        try { if (transport != null) transport.close(); } catch (Exception ignored) {}
    }

    @Override
    public void processPdu(CommandResponderEvent e) {
        try {
            if (e == null || e.getPDU() == null) return;

            UdpAddress peer = (UdpAddress) e.getPeerAddress();

            // 1) Varbinds crudos OID -> valor (String)
            Map<String, Object> varbinds = new LinkedHashMap<>();
            for (VariableBinding vb : e.getPDU().getVariableBindings()) {
                varbinds.put(vb.getOid().toDottedString(), vb.getVariable().toString());
            }

            // 2) Enriquecer con MIB si está configurado
            if (mibEnricher != null) varbinds = mibEnricher.enrich(varbinds);

            // 3) Asegurar alias snmpTrapOID si existe
            Object trapOid = varbinds.get("1.3.6.1.6.3.1.1.4.1.0");
            if (trapOid != null && !varbinds.containsKey("snmpTrapOID")) {
                varbinds.put("snmpTrapOID", trapOid.toString());
            }

            // 4) Namespace “snmp.varbinds.*” (útil para reglas por plugin)
            Map<String,Object> attrs = new LinkedHashMap<>(varbinds);
            Map<String,Object> snmpNs = new LinkedHashMap<>();
            snmpNs.put("varbinds", new LinkedHashMap<>(varbinds));
            attrs.put("snmp", snmpNs);

            // 5) Emitir evento normalizado
            NormalizedEvent evt = NormalizedEvent.builder()
                    .ts(Instant.now())
                    .protocol(Protocol.SNMP_TRAP)
                    .kind(EventKind.TRAP)
                    .source(new Source(
                            peer.getInetAddress().getHostAddress(),
                            peer.getPort(),
                            null,
                            Transport.UDP))
                    .pluginId(pluginId)
                    .tags(Map.of("pduType", String.valueOf(e.getPDU().getType())))
                    .attributes(attrs)
                    .bytes(e.getPDU().toArray().length)  // aproximado
                    .build();

            listener.accept(evt);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
