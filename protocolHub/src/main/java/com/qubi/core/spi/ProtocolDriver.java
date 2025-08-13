package com.qubi.core.spi;

import java.io.Closeable;

public interface ProtocolDriver extends Closeable {
    void start() throws Exception;
    void setListener(EventListener listener);
}
