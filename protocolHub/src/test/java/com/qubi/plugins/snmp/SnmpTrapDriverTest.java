package com.qubi.plugins.snmp;

import com.qubi.core.model.EventKind;
import com.qubi.core.model.NormalizedEvent;
import com.qubi.core.model.Protocol;
import com.qubi.core.model.Transport;
import org.junit.jupiter.api.*;
import org.snmp4j.*;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.net.DatagramSocket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class SnmpTrapDriverTest {

    private SnmpTrapDriver driver;
    private BlockingQueue<NormalizedEvent> queue;

    private int testPort;

    @BeforeEach
    void setUp() throws Exception {
        queue = new ArrayBlockingQueue<>(8);
        testPort = findFreeUdpPort();
    }

    @AfterEach
    void tearDown() {
        if (driver != null) {
            try { driver.stop(); } catch (Exception ignored) {}
        }
    }

    // ========== SNMPv2c ==========

    @Test
    void receivesTrap_v2c() throws Exception {
        driver = new SnmpTrapDriver(testPort, "snmp4j-trap");
        driver.setListener(queue::offer);
        driver.start();
        Thread.sleep(150); // pequeña espera para que escuche

        sendTrapV2("127.0.0.1", testPort);

        NormalizedEvent evt = queue.poll(3, TimeUnit.SECONDS);
        assertNotNull(evt, "No llegó el trap v2c");
        assertEquals(Protocol.SNMP_TRAP, evt.protocol());
        assertEquals(EventKind.TRAP, evt.kind());
        assertEquals("snmp4j-trap", evt.pluginId());
        assertEquals(Transport.UDP, evt.source().transport());
        assertTrue(evt.attributes().containsKey("snmpTrapOID"), "Falta snmpTrapOID");

        // opcionales
        Map<String, Object> attrs = evt.attributes();
        assertEquals("1.3.6.1.6.3.1.1.5.3", String.valueOf(attrs.get("snmpTrapOID"))); // linkDown
    }

    // ========== SNMPv3 (authNoPriv con SHA) ==========

    @Test
    void receivesTrap_v3_authNoPriv_SHA() throws Exception {
        SnmpTrapDriver.SnmpV3User user = SnmpTrapDriver.SnmpV3User.withSHA1Auth("testuser", "testpassword");

        driver = new SnmpTrapDriver(testPort, "snmp4j-trap", List.of(user));
        driver.setListener(queue::offer);
        driver.start();
        Thread.sleep(150);

        sendTrapV3_authNoPriv_SHA("127.0.0.1", testPort, "testuser", "testpassword");

        NormalizedEvent evt = queue.poll(3, TimeUnit.SECONDS);
        assertNotNull(evt, "No llegó el trap v3 authNoPriv (SHA)");
        assertEquals(Protocol.SNMP_TRAP, evt.protocol());
        assertEquals(EventKind.TRAP, evt.kind());
        assertEquals("snmp4j-trap", evt.pluginId());
        assertTrue(evt.attributes().containsKey("snmpTrapOID"));
    }

    // ========== SNMPv3 (authPriv con SHA + AES128) ==========

    @Test
    void receivesTrap_v3_authPriv_SHA_AES128() throws Exception {
        SnmpTrapDriver.SnmpV3User user = new SnmpTrapDriver.SnmpV3User(
                "secureuser", AuthSHA.ID, "authpass123", PrivAES128.ID, "privpass123");

        driver = new SnmpTrapDriver(testPort, "snmp4j-trap", List.of(user));
        driver.setListener(queue::offer);
        driver.start();
        Thread.sleep(150);

        sendTrapV3_authPriv_SHA_AES("127.0.0.1", testPort, "secureuser", "authpass123", "privpass123");

        NormalizedEvent evt = queue.poll(3, TimeUnit.SECONDS);
        assertNotNull(evt, "No llegó el trap v3 authPriv (SHA+AES128)");
        assertEquals(Protocol.SNMP_TRAP, evt.protocol());
        assertEquals(EventKind.TRAP, evt.kind());
        assertEquals("snmp4j-trap", evt.pluginId());
        assertTrue(evt.attributes().containsKey("snmpTrapOID"));
    }

    // ============================================================
    // Helpers
    // ============================================================

    private static int findFreeUdpPort() throws Exception {
        // Para tests está bien usar TCP para reservar un puerto y luego usarlo en UDP,
        // ya que buscamos evitar colisiones. Alternativamente, fijá puertos fijos.
        try (DatagramSocket socket = new DatagramSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private void sendTrapV2(String host, int port) throws Exception {
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(1);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);

        PDU pdu = new PDU();
        pdu.setType(PDU.TRAP);
        // snmpTrapOID = linkDown
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.6.3.1.1.5.3")));
        // ifIndex = 1
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.2.2.1.1"), new Integer32(1)));

        snmp.send(pdu, target);
        snmp.close();
    }

    private void sendTrapV3_authNoPriv_SHA(String host, int port, String username, String authPassword) throws Exception {
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        // Protocolos y USM/MPv3
        SecurityProtocols.getInstance().addDefaultProtocols();
        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

        transport.listen();

        // Usuario authNoPriv (SHA)
        UsmUser usmUser = new UsmUser(
                new OctetString(username),
                AuthSHA.ID, new OctetString(authPassword),
                null, null
        );
        snmp.getUSM().addUser(new OctetString(username), usmUser);

        UserTarget target = new UserTarget();
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(1);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
        target.setSecurityName(new OctetString(username));

        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.TRAP);
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.6.3.1.1.5.3"))); // linkDown
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.2.2.1.1"), new Integer32(1)));

        snmp.send(pdu, target);
        snmp.close();
    }

    private void sendTrapV3_authPriv_SHA_AES(String host, int port, String username, String authPassword, String privPassword) throws Exception {
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        // Protocolos y USM/MPv3
        SecurityProtocols.getInstance().addDefaultProtocols();
        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

        transport.listen();

        // Usuario authPriv (SHA + AES128)
        UsmUser usmUser = new UsmUser(
                new OctetString(username),
                AuthSHA.ID, new OctetString(authPassword),
                PrivAES128.ID, new OctetString(privPassword)
        );
        snmp.getUSM().addUser(new OctetString(username), usmUser);

        UserTarget target = new UserTarget();
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(1);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString(username));

        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.TRAP);
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.6.3.1.1.5.3"))); // linkDown
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.2.2.1.1"), new Integer32(1)));

        snmp.send(pdu, target);
        snmp.close();
    }
}
