package com.qubi.core.spi;

import com.qubi.core.model.NormalizedEvent;

@FunctionalInterface
public interface EventListener {
    void onEvent(NormalizedEvent event);
}
