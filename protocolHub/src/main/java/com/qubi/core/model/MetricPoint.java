package com.qubi.core.model;

import java.util.Map;

public record MetricPoint(
        String name,          // p.ej. "net.if.up"
        double value,         // 0/1, porcentaje, rate, etc.
        long ts,              // epoch millis
        Map<String,String> tags, // device, ifIndex, tenant...
        String unit,          // "%", "bool", "bps"...
        String type           // "gauge" | "counter" | "rate"
) {}
