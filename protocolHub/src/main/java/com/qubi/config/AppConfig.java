package com.qubi.config;



import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AppConfig {
    public List<DriverConfig> drivers;
    public SnmpConfig snmp;                // <— modela el bloque snmp

    public static class DriverConfig {
        public String pluginId;
        public int port;
    }
    public static class SnmpConfig {
        public String mibsDir;               // ej: "/usr/share/snmp/mibs"
        public List<String> modules;         // ej: ["SNMPv2-SMI","SNMPv2-MIB","IF-MIB"]
    }
}

