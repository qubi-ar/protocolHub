package com.qubi.plugins.snmp;

import com.qubi.core.model.NormalizedEvent;
import com.qubi.core.model.Protocol;
import com.qubi.core.model.EventKind;
import com.qubi.core.model.Source;
import com.qubi.core.model.Transport;
import org.junit.jupiter.api.*;

import org.snmp4j.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class SnmpTrapDriverTest {

    private SnmpTrapDriver driver;
    private final int PORT = 9162; // usa puerto alto para no requerir root
    private BlockingQueue<NormalizedEvent> queue;

    @BeforeEach
    void setUp() throws Exception {
        queue = new ArrayBlockingQueue<>(5);
        driver = new SnmpTrapDriver(PORT, "snmp4j-trap");
        driver.setListener(queue::offer);
        driver.start();
        // pequeña espera para que el listener arranque
        Thread.sleep(200);
    }

    @AfterEach
    void tearDown() {
        try { driver.stop(); } catch (Exception ignored) {}
    }

    @Test
    void receivesTrapAndBuildsEvent() throws Exception {
        // 1) Enviar trap SNMP v2c básico
        sendTestTrap("127.0.0.1", PORT);

        // 2) Recibir y validar
        NormalizedEvent evt = queue.poll(3, TimeUnit.SECONDS);
        assertNotNull(evt, "No llegó el trap");
        assertEquals(Protocol.SNMP_TRAP, evt.protocol());
        assertEquals(EventKind.TRAP, evt.kind());
        assertEquals("snmp4j-trap", evt.pluginId());
        assertTrue(evt.attributes().containsKey("snmpTrapOID"),
                "Falta snmpTrapOID en atributos");
    }

    private void sendTestTrap(String host, int port) throws Exception {
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);
        transport.listen();

        // Target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(1);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);

        // PDU tipo TRAP
        PDU pdu = new PDU();
        pdu.setType(PDU.TRAP);
        // snmpTrapOID OID de ejemplo (linkDown)
        OID trapOid = new OID("1.3.6.1.6.3.1.1.5.3");
        pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, trapOid));
        // valor adicional (ifIndex=1)
        pdu.add(new VariableBinding(new OID("1.3.6.1.2.1.2.2.1.1"), new Integer32(1)));

        snmp.send(pdu, target);
        snmp.close();
    }
}
