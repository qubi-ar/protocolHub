package com.qubi.core.normalize;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.qubi.core.model.*;

import java.io.InputStream;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Normalizador agnóstico de plugins. Soporta match por:
 * - protocol (obligatorio para reglas específicas)
 * - plugin (opcional)
 * - transport (opcional)
 * - sourcePort (opcional)
 * - body_regex (opcional, con grupos nombrados)
 * - trap_oid (opcional; busca en attributes)
 * - attr_exists (opcional; lista de paths en attributes/tags/source.*)
 * - attr_regex (opcional; mapa path->regex)
 *
 * set: tags/attributes/severity con placeholders ${...} (source.*, tags.*, attributes.*, captures.*)
 */
public class YamlEventNormalizer {
    private final List<Rule> rules;

    public YamlEventNormalizer(InputStream yaml) {
        try {
            ObjectMapper om = new ObjectMapper(new YAMLFactory());
            RuleConfig cfg = om.readValue(yaml, RuleConfig.class);
            this.rules = compile(cfg);
        } catch (Exception e) {
            throw new RuntimeException("Error loading normalization rules", e);
        }
    }

    public NormalizedEvent normalize(NormalizedEvent e) {
        Map<String,String> outTags = new LinkedHashMap<>(e.tags());
        Map<String,Object> outAttrs = new LinkedHashMap<>(e.attributes());
        Severity newSev = e.severity();

        for (Rule r : rules) {
            Matcher bodyMatcher = r.bodyRe != null && e.body()!=null ? r.bodyRe.matcher(e.body()) : null;
            if (!r.matches(e, bodyMatcher)) continue;

            Map<String,String> caps = extractNamedCaptures(bodyMatcher, r.bodyRe);
            Map<String,Object> ctx = buildCtx(e, caps);

            // tags
            for (var en : r.setTags.entrySet()) {
                String v = interpolate(en.getValue(), ctx);
                if (v != null && !v.isBlank()) outTags.put(en.getKey(), v);
            }
            // attributes
            for (var en : r.setAttrs.entrySet()) {
                String v = interpolate(en.getValue(), ctx);
                if (v != null && !v.isBlank()) outAttrs.put(en.getKey(), v);
            }
            // severity
            if (r.severity != null) newSev = Severity.valueOf(r.severity);
        }

        return NormalizedEvent.builder()
                .id(e.id())
                .ts(e.ts())
                .receivedTs(e.receivedTs())
                .protocol(e.protocol())
                .kind(e.kind())
                .source(e.source())
                .pluginId(e.pluginId())
                .tenant(e.tenant())
                .severity(newSev)
                .body(e.body())
                .tags(outTags)
                .attributes(outAttrs)
                .bytes(e.bytes())
                .build();
    }

    // ===== Helpers =====

    private static Map<String,Object> buildCtx(NormalizedEvent e, Map<String,String> caps){
        Map<String,Object> ctx = new HashMap<>();
        ctx.put("captures", caps);

        Map<String,Object> source = new HashMap<>();
        source.put("ip", e.source().host());
        source.put("port", e.source().port());
        source.put("transport", e.source().transport().name());
        ctx.put("source", source);

        Map<String,Object> attrs = new HashMap<>();
        e.attributes().forEach(attrs::put);
        ctx.put("attributes", attrs);

        Map<String,Object> tags = new HashMap<>();
        e.tags().forEach(tags::put);
        ctx.put("tags", tags);

        if (e.pluginId()!=null) ctx.put("plugin", e.pluginId());
        ctx.put("protocol", e.protocol().name());
        return ctx;
    }

    private static String interpolate(String tpl, Map<String,Object> ctx){
        if (tpl == null) return null;
        Matcher m = Pattern.compile("\\$\\{([^}]+)}").matcher(tpl);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String path = m.group(1);
            Object val = getPath(ctx, path);
            m.appendReplacement(sb, Matcher.quoteReplacement(val == null ? "" : String.valueOf(val)));
        }
        m.appendTail(sb);
        String out = sb.toString();
        return out.isBlank() ? null : out;
    }

    @SuppressWarnings("unchecked")
    private static Object getPath(Map<String,Object> root, String path){
        String[] parts = path.split("\\.");
        Object cur = root;
        for (String p : parts) {
            if (!(cur instanceof Map<?,?> map)) return null;
            cur = map.get(p);
            if (cur == null) return null;
        }
        return cur;
    }

    private static Map<String,String> extractNamedCaptures(Matcher m, Pattern p){
        Map<String,String> caps = new HashMap<>();
        if (m == null || p == null) return caps;
        if (!m.find()) return caps;
        // Extraer nombres ?<name> del patrón
        Matcher nm = Pattern.compile("\\(\\?<([a-zA-Z][a-zA-Z0-9_]*)>").matcher(p.pattern());
        while (nm.find()) {
            String name = nm.group(1);
            try {
                String v = m.group(name);
                if (v != null) caps.put(name, v);
            } catch (Exception ignored) {}
        }
        return caps;
    }

    // ===== Reglas =====

    private static List<Rule> compile(RuleConfig cfg){
        List<Rule> list = new ArrayList<>();
        if (cfg == null || cfg.rules == null) return list;
        for (var r : cfg.rules) {
            Pattern bodyRe = r.match.body_regex != null ? Pattern.compile(r.match.body_regex) : null;

            // compilar attr_regex
            Map<String,Pattern> attrRegex = new HashMap<>();
            if (r.match.attr_regex != null) {
                for (var en : r.match.attr_regex.entrySet()) {
                    attrRegex.put(en.getKey(), Pattern.compile(en.getValue()));
                }
            }
            list.add(new Rule(
                    r.match.protocol,
                    r.match.plugin,
                    r.match.transport,
                    r.match.source_port,
                    r.match.trap_oid,
                    r.match.attr_exists != null ? List.copyOf(r.match.attr_exists) : List.of(),
                    attrRegex,
                    bodyRe,
                    r.set != null && r.set.tags != null ? r.set.tags : Map.of(),
                    r.set != null && r.set.attributes != null ? r.set.attributes : Map.of(),
                    r.set != null ? r.set.severity : null
            ));
        }
        return list;
    }

    private record Rule(
            String protocol, String plugin, String transport,
            Integer sourcePort, String trapOid,
            List<String> attrExists, Map<String,Pattern> attrRegex,
            Pattern bodyRe,
            Map<String,String> setTags, Map<String,String> setAttrs, String severity
    ){
        boolean matches(NormalizedEvent e, Matcher bodyMatcher){
            // protocol
            if (protocol != null && !protocol.equals(e.protocol().name())) return false;
            // plugin
            if (plugin != null && (e.pluginId()==null || !plugin.equals(e.pluginId()))) return false;
            // transport
            if (transport != null && !transport.equalsIgnoreCase(e.source().transport().name())) return false;
            // source port
            if (sourcePort != null && e.source().port() != sourcePort) return false;
            // trap OID (buscar en attributes; soporta namespaces)
            // trap OID (buscar en attributes; soporta namespaces)
            if (trapOid != null) {
                String found = asString(resolvePath(e, "attributes.1.3.6.1.6.3.1.1.4.1.0"));
                if (found == null) {
                    // namespaces típicos
                    found = asString(resolvePath(e, "attributes.snmp.varbinds.1.3.6.1.6.3.1.1.4.1.0"));
                    if (found == null) found = asString(resolvePath(e, "attributes.snmpTrapOID"));
                }
                if (!trapOid.equals(found)) return false;
            }
            // body regex
            if (bodyRe != null) {
                if (e.body()==null) return false;
                if (bodyMatcher==null || !bodyMatcher.find()) return false;
            }
            // attr_exists
            for (String path : attrExists) {
                Object v = resolvePath(e, path);
                if (v == null || (v instanceof CharSequence cs && cs.toString().isBlank())) return false;
            }
            // attr_regex
            for (var en : attrRegex.entrySet()) {
                Object v = resolvePath(e, en.getKey());
                if (v == null) return false;
                if (!en.getValue().matcher(String.valueOf(v)).find()) return false;
            }
            return true;
        }

        private static Object resolvePath(NormalizedEvent e, String path) {
            // paths soportados: "attributes.*", "tags.*", "source.ip", "source.port", "protocol", "plugin"
            Map<String,Object> root = new HashMap<>();
            root.put("attributes", e.attributes());
            Map<String,Object> tags = new HashMap<>();
            e.tags().forEach(tags::put);
            root.put("tags", tags);
            Map<String,Object> source = new HashMap<>();
            source.put("ip", e.source().host());
            source.put("port", e.source().port());
            source.put("transport", e.source().transport().name());
            root.put("source", source);
            root.put("protocol", e.protocol().name());
            if (e.pluginId()!=null) root.put("plugin", e.pluginId());
            return getPath(root, path);
        }

        @SuppressWarnings("unchecked")
        private static Object getPath(Map<String,Object> root, String path){
            String[] parts = path.split("\\.");
            Object cur = root;
            for (String p : parts) {
                if (!(cur instanceof Map<?,?> map)) return null;
                cur = map.get(p);
                if (cur == null) return null;
            }
            return cur;
        }

        private static String asString(Object o){ return o==null? null : String.valueOf(o); }
    }

    // ===== Config YAML (embebida para simplificar) =====

    public static final class RuleConfig {
        public List<RuleDef> rules;

        public static final class RuleDef {
            public Match match = new Match();
            public SetOp set = new SetOp();
        }
        public static final class Match {
            public String protocol;          // "SYSLOG" | "SNMP_TRAP" | ...
            public String plugin;            // opcional
            public String transport;         // "UDP" | "TCP" | "TLS" | "GRPC" (opcional)
            public Integer source_port;      // opcional
            public String body_regex;        // opcional
            public String trap_oid;          // opcional
            public List<String> attr_exists; // opcional
            public Map<String,String> attr_regex; // opcional
        }
        public static final class SetOp {
            public Map<String,String> tags;        // k -> template
            public Map<String,String> attributes;  // k -> template
            public String severity;                // ej: "WARN"
        }
    }
}
