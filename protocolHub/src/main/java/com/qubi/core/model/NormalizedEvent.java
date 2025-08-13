package com.qubi.core.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.*;

@JsonInclude(JsonInclude.Include.NON_NULL)
public final class NormalizedEvent {
    // --- obligatorios ---
    private final String id;              // UUID o hash determinístico
    private final Instant ts;             // timestamp del evento (del device si viene)
    private final Instant receivedTs;     // timestamp de recepción
    private final Protocol protocol;      // SNMP_TRAP, SYSLOG, etc.
    private final EventKind kind;         // TRAP, LOG, FLOW, TELEMETRY
    private final Source source;          // ip, puerto, transporte

    // --- nuevos / opcionales ---
    private final String pluginId;        // ej: "snmp4j-trap", "syslog-udp", "line-udp"

    // --- opcionales útiles ---
    private final String tenant;          // multi-tenant (si aplica)
    private final Severity severity;      // severidad (si aplica)
    private final String body;            // texto/log crudo (syslog) o explicación
    private final Metric metric;          // métrica numérica unitaria (opcional)
    private final Map<String, String> tags;        // etiquetas (host, ifIndex, facility,…)
    private final Map<String, Object> attributes;  // payload parseado (OIDs→valor, etc.)
    private final Integer bytes;          // tamaño del mensaje recibido

    @JsonCreator
    private NormalizedEvent(
            @JsonProperty("id") String id,
            @JsonProperty(value="ts", required=true) Instant ts,
            @JsonProperty("receivedTs") Instant receivedTs,
            @JsonProperty(value="protocol", required=true) Protocol protocol,
            @JsonProperty(value="kind", required=true) EventKind kind,
            @JsonProperty(value="source", required=true) Source source,
            @JsonProperty("pluginId") String pluginId,
            @JsonProperty("tenant") String tenant,
            @JsonProperty("severity") Severity severity,
            @JsonProperty("body") String body,
            @JsonProperty("metric") Metric metric,
            @JsonProperty("tags") Map<String,String> tags,
            @JsonProperty("attributes") Map<String,Object> attributes,
            @JsonProperty("bytes") Integer bytes
    ) {
        this.id = (id != null) ? id : UUID.randomUUID().toString();
        this.ts = Objects.requireNonNull(ts, "ts");
        this.receivedTs = (receivedTs != null) ? receivedTs : Instant.now();
        this.protocol = Objects.requireNonNull(protocol, "protocol");
        this.kind = Objects.requireNonNull(kind, "kind");
        this.source = Objects.requireNonNull(source, "source");
        this.pluginId = pluginId;
        this.tenant = tenant;
        this.severity = severity;
        this.body = body;
        this.metric = metric;
        this.tags = (tags == null) ? Map.of() : Map.copyOf(tags);
        this.attributes = (attributes == null) ? Map.of() : Map.copyOf(attributes);
        this.bytes = bytes;
    }

    // --- getters ---
    public String id() { return id; }
    public Instant ts() { return ts; }
    public Instant receivedTs() { return receivedTs; }
    public Protocol protocol() { return protocol; }
    public EventKind kind() { return kind; }
    public Source source() { return source; }
    public String pluginId() { return pluginId; }
    public String tenant() { return tenant; }
    public Severity severity() { return severity; }
    public String body() { return body; }
    public Metric metric() { return metric; }
    public Map<String, String> tags() { return tags; }
    public Map<String, Object> attributes() { return attributes; }
    public Integer bytes() { return bytes; }

    // --- builder ---
    public static Builder builder() { return new Builder(); }
    public static final class Builder {
        private String id;
        private Instant ts = Instant.now();
        private Instant receivedTs;
        private Protocol protocol;
        private EventKind kind;
        private Source source;
        private String pluginId;
        private String tenant;
        private Severity severity;
        private String body;
        private Metric metric;
        private Map<String,String> tags = new LinkedHashMap<>();
        private Map<String,Object> attributes = new LinkedHashMap<>();
        private Integer bytes;

        public Builder id(String id){ this.id = id; return this; }
        public Builder ts(Instant ts){ this.ts = ts; return this; }
        public Builder receivedTs(Instant rt){ this.receivedTs = rt; return this; }
        public Builder protocol(Protocol p){ this.protocol = p; return this; }
        public Builder kind(EventKind k){ this.kind = k; return this; }
        public Builder source(Source s){ this.source = s; return this; }
        public Builder pluginId(String pid){ this.pluginId = pid; return this; }
        public Builder tenant(String t){ this.tenant = t; return this; }
        public Builder severity(Severity s){ this.severity = s; return this; }
        public Builder body(String b){ this.body = b; return this; }
        public Builder metric(Metric m){ this.metric = m; return this; }
        public Builder tag(String k, String v){ this.tags.put(k,v); return this; }
        public Builder tags(Map<String,String> t){ if(t!=null) this.tags.putAll(t); return this; }
        public Builder attr(String k, Object v){ this.attributes.put(k,v); return this; }
        public Builder attributes(Map<String,Object> a){ if(a!=null) this.attributes.putAll(a); return this; }
        public Builder bytes(Integer b){ this.bytes = b; return this; }

        public NormalizedEvent build() {
            return new NormalizedEvent(id, ts, receivedTs, protocol, kind, source,
                    pluginId, tenant, severity, body, metric, tags, attributes, bytes);
        }
    }
}
