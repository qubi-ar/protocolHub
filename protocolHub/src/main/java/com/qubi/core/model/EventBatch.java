package com.qubi.core.model;

import java.util.List;

public record EventBatch(
        List<NormalizedEvent> events,
        String sourceId,       // opcional: id del driver/emisor interno
        long sequence          // opcional: número de secuencia
) {}
