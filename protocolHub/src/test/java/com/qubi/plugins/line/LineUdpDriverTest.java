package com.qubi.plugins.line;

import com.qubi.core.model.NormalizedEvent;
import org.junit.jupiter.api.*;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

class LineUdpDriverTest {

    private LineUdpDriver driver;
    private final int PORT = 5515;

    // cola para capturar eventos del listener
    static class TestState { static BlockingQueue<NormalizedEvent> queue; }

    @BeforeEach
    void setUp() throws Exception {
        BlockingQueue<NormalizedEvent> queue = new ArrayBlockingQueue<>(10);
        driver = new LineUdpDriver(PORT, "line-udp");
        driver.setListener(queue::offer);  // usa Consumer<NormalizedEvent>
        driver.start();
        TestState.queue = queue;
    }

    @AfterEach
    void tearDown() {
        try { driver.stop(); } catch (Exception ignored) {}
    }

    @Test
    void receivesOneLineAndBuildsEvent() throws Exception {
        String msg = "hello protocolHub";
        sendUdp("127.0.0.1", PORT, msg);

        NormalizedEvent evt = TestState.queue.poll(2, TimeUnit.SECONDS);
        assertNotNull(evt, "no llegó evento");

        assertNotNull(evt.ts());
        assertEquals("hello protocolHub", evt.body());
        assertEquals("127.0.0.1", evt.source().host());
        assertEquals(Integer.valueOf(msg.getBytes().length), evt.bytes());
        assertEquals("line-udp", evt.pluginId());
    }

    private static void sendUdp(String host, int port, String text) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            byte[] buf = text.getBytes();
            DatagramPacket packet = new DatagramPacket(buf, buf.length,
                    InetAddress.getByName(host), port);
            socket.send(packet);
        }
    }
}
