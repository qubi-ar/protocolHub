package com.qubi.core.model;

import java.net.InetAddress;

public record Source(
        String host,          // IP textual (p.ej. "192.168.1.10")
        int port,             // puerto origen
        String hostname,      // opcional: nombre reportado
        Transport transport   // UDP/TCP/TLS/GRPC
) {}
