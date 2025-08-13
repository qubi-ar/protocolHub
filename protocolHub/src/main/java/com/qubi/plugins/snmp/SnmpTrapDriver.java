package com.qubi.plugins.snmp;

import com.qubi.core.model.*;
import com.qubi.plugins.snmp.mib.MibEnricher;
import org.snmp4j.*;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
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

    // SNMP v3 configuration
    private List<SnmpV3User> v3Users;
    private boolean enableV3 = false;

    public SnmpTrapDriver(int port) { this(port, "snmp4j-trap"); }
    public SnmpTrapDriver(int port, String pluginId) {
        this.port = port;
        this.pluginId = pluginId;
    }

    public SnmpTrapDriver(int port, String pluginId, List<SnmpV3User> v3Users) {
        this.port = port;
        this.pluginId = pluginId;
        this.v3Users = v3Users;
        this.enableV3 = v3Users != null && !v3Users.isEmpty();
    }

    public void setListener(Consumer<NormalizedEvent> l) { this.listener = (l != null) ? l : e -> {}; }
    public void setMibEnricher(MibEnricher enricher) { this.mibEnricher = enricher; }
    public void setV3Users(List<SnmpV3User> users) { 
        this.v3Users = users;
        this.enableV3 = users != null && !users.isEmpty();
    }

    public void start() throws Exception {
        UdpAddress addr = new UdpAddress("0.0.0.0/" + port);
        transport = new DefaultUdpTransportMapping(addr);
        snmp = new Snmp(transport);
        
        // Configure SNMP v3 security if enabled
        if (enableV3) {
            configureSnmpV3Security();
        }
        
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

    private void configureSnmpV3Security() {
        // 0) Protocolos por defecto (MD5/SHA/AES/DES, etc.)
        SecurityProtocols securityProtocols = SecurityProtocols.getInstance();
        securityProtocols.addDefaultProtocols();
        securityProtocols.addAuthenticationProtocol(new AuthMD5());
        securityProtocols.addAuthenticationProtocol(new AuthSHA());
        securityProtocols.addPrivacyProtocol(new PrivDES());
        securityProtocols.addPrivacyProtocol(new PrivAES128());
        // 1) USM con engineId local y registrarlo en SecurityModels
        USM usm = new USM(SecurityProtocols.getInstance(),
                new OctetString(MPv3.createLocalEngineID()), 0);
        SecurityModels.getInstance().addSecurityModel(usm);

        // 2) Agregar MPv3 al dispatcher del Snmp
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

        // 3) Registrar usuarios con la sobrecarga que incluye securityName
        if (v3Users != null) {
            for (SnmpV3User user : v3Users) {
                UsmUser usmUser = new UsmUser(
                        new OctetString(user.getUsername()),
                        user.getAuthProtocol(),
                        user.getAuthPassphrase() != null ? new OctetString(user.getAuthPassphrase()) : null,
                        user.getPrivProtocol(),
                        user.getPrivPassphrase() != null ? new OctetString(user.getPrivPassphrase()) : null
                );
                // IMPORTANTE: incluir el securityName en la llamada
                snmp.getUSM().addUser(new OctetString(user.getUsername()), usmUser);
            }
        }
    }


    public static class SnmpV3User {
        private final String username;
        private final OID authProtocol;
        private final String authPassphrase;
        private final OID privProtocol;
        private final String privPassphrase;
        
        public SnmpV3User(String username) {
            this(username, null, null, null, null);
        }
        
        public SnmpV3User(String username, OID authProtocol, String authPassphrase) {
            this(username, authProtocol, authPassphrase, null, null);
        }
        
        public SnmpV3User(String username, OID authProtocol, String authPassphrase, 
                         OID privProtocol, String privPassphrase) {
            this.username = username;
            this.authProtocol = authProtocol;
            this.authPassphrase = authPassphrase;
            this.privProtocol = privProtocol;
            this.privPassphrase = privPassphrase;
        }
        
        public String getUsername() { return username; }
        public OID getAuthProtocol() { return authProtocol; }
        public String getAuthPassphrase() { return authPassphrase; }
        public OID getPrivProtocol() { return privProtocol; }
        public String getPrivPassphrase() { return privPassphrase; }
        
        // Helper methods for common protocols
        public static SnmpV3User withMD5Auth(String username, String authPassphrase) {
            return new SnmpV3User(username, AuthMD5.ID, authPassphrase);
        }
        
        public static SnmpV3User withSHA1Auth(String username, String authPassphrase) {
            return new SnmpV3User(username, AuthSHA.ID, authPassphrase);
        }
        
        public static SnmpV3User withMD5AuthDESPriv(String username, String authPassphrase, String privPassphrase) {
            return new SnmpV3User(username, AuthMD5.ID, authPassphrase, PrivDES.ID, privPassphrase);
        }
        
        public static SnmpV3User withSHA1AuthDESPriv(String username, String authPassphrase, String privPassphrase) {
            return new SnmpV3User(username, AuthSHA.ID, authPassphrase, PrivDES.ID, privPassphrase);
        }
    }
}
