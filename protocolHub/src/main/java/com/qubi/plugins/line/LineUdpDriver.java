package com.qubi.plugins.line;

import com.qubi.core.model.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class LineUdpDriver {
    private final int port;
    private final String pluginId;
    private Consumer<NormalizedEvent> listener;
    private DatagramSocket socket;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    public LineUdpDriver(int port, String pluginId) {
        this.port = port;
        this.pluginId = pluginId;
    }

    public LineUdpDriver pluginId(String id) {
        return new LineUdpDriver(this.port, id);
    }

    public void setListener(Consumer<NormalizedEvent> listener) {
        this.listener = listener;
    }

    public void start() throws SocketException {
        socket = new DatagramSocket(port);
        executor.submit(this::receiveLoop);
    }

    public void stop() {
        if (socket != null && !socket.isClosed()) socket.close();
        executor.shutdownNow();
    }

    private void receiveLoop() {
        byte[] buf = new byte[8192];
        while (!Thread.currentThread().isInterrupted()) {
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);

                String body = new String(packet.getData(), 0, packet.getLength()).trim();

                NormalizedEvent evt = NormalizedEvent.builder()
                        .ts(Instant.now())
                        .protocol(Protocol.valueOf("SYSLOG")) // o un Protocol.LINE si lo tenés definido
                        .kind(EventKind.LOG)
                        .source(new Source(packet.getAddress().getHostAddress(),
                                packet.getPort(),
                                null,
                                Transport.UDP))
                        .pluginId(pluginId)
                        .body(body)
                        .tags(Map.of("source_ip", packet.getAddress().getHostAddress()))
                        .attr("raw", body)
                        .bytes(packet.getLength())
                        .build();

                if (listener != null) {
                    listener.accept(evt);
                }
            } catch (IOException e) {
                if (!socket.isClosed()) {
                    e.printStackTrace();
                }
                break;
            }
        }
    }
}
