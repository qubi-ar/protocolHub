package com.qubi.core.model;

public record Metric(
        String name,          // ej. "cpu.utilization"
        double value,         // valor numérico
        String unit           // ej. "%", "bps", "packets"
) {}
