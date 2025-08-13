package com.qubi.core.model;

public enum EventKind {
    TRAP,        // SNMP trap/notification
    LOG,         // syslog/evento textual
    FLOW,        // netflow/ipfix/sflow
    TELEMETRY    // gNMI/streaming
}
