package com.qubi.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AppConfig {
    public List<DriverConfig> drivers = new ArrayList<>();
    public SnmpConfig snmp;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class DriverConfig {
        public String pluginId;
        public int port;

        // —— OPCIONALES para alto caudal (drivers que los soporten) ——
        /** Capacidad de cola entre receptor y workers (backpressure). */
        public Integer queueCapacity;              // default: 65536
        /** Cantidad de workers por puerto/proceso. */
        public Integer workerThreads;              // default: max(2, cores)
        /** Política cuando la cola está llena: BLOCK o DROP_NEWEST. */
        public String  overflowPolicy;             // default: "BLOCK"
        /** Timeout de offer() cuando overflowPolicy=BLOCK (ms). */
        public Long    offerTimeoutMs;             // default: 2
        /** SO_RCVBUF solicitado (bytes). */
        public Integer udpReceiveBufferBytes;      // default: 128*1024*1024
        /** Tamaño máximo de datagrama a recibir (bytes). */
        public Integer maxInboundMessageSize;      // default: 64*1024
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SnmpConfig {
        public String mibsDir;
        public List<String> modules;

        public TrapConfig trap = new TrapConfig();

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class TrapConfig {
            /** Puerto para el listener SNMPv3 (si se usa). Si es null, se usa el del driver. */
            public Integer port;
            public String pluginId = "snmp4j-trap";
            public V3Config v3 = new V3Config();

            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class V3Config {
                public boolean enabled = false;
                public List<V3User> users = new ArrayList<>();

                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class V3User {
                    public String username;
                    public String authProtocol = "NONE";   // NONE|MD5|SHA|...
                    public String authPassphrase;          // ≥8 si auth!=NONE
                    public String privProtocol = "NONE";   // NONE|DES|AES|AES128|...
                    public String privPassphrase;          // ≥8 si priv!=NONE
                }
            }
        }
    }
}
