// plugins/snmp/SnmpTrapNormalizer.java
package com.qubi.plugins.snmp;
import com.qubi.core.model.NormalizedEvent;
import com.qubi.core.model.Severity;
import com.qubi.core.spi.EventNormalizer;
import com.qubi.core.normalize.RuleConfig;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.regex.Pattern;

public class SnmpTrapNormalizer implements EventNormalizer {
  private static final String DEFAULT_TRAP_OID_KEY = "snmpTrapOID";
  private final List<RuleConfig.Rule> rules;
  private final String trapOidKey;

  public SnmpTrapNormalizer() {
    this.rules = List.of();
    this.trapOidKey = DEFAULT_TRAP_OID_KEY;
  }

  public SnmpTrapNormalizer(List<RuleConfig.Rule> rules) {
    this.rules = rules;
    this.trapOidKey = DEFAULT_TRAP_OID_KEY;
  }

  public SnmpTrapNormalizer(List<RuleConfig.Rule> rules, String trapOidKey) {
    this.rules = rules;
    this.trapOidKey = trapOidKey != null ? trapOidKey : DEFAULT_TRAP_OID_KEY;
  }

  @Override public boolean supports(NormalizedEvent e) {
    return "snmp4j-trap".equals(e.pluginId());
  }

  @Override public NormalizedEvent normalize(NormalizedEvent e) {
    Object trapOid = e.attributes().get(trapOidKey);
    String trapOidStr = String.valueOf(trapOid);
    
    for (RuleConfig.Rule rule : rules) {
      if (matches(rule.match(), e, trapOidStr)) {
        return applyRule(rule, e);
      }
    }
    return e;
  }

  private boolean matches(RuleConfig.Match match, NormalizedEvent e, String trapOid) {
    if (match.protocol() != null && !match.protocol().equals(e.protocol().name())) {
      return false;
    }
    if (match.trap_oid() != null && !match.trap_oid().equals(trapOid)) {
      return false;
    }
    return true;
  }

  private NormalizedEvent applyRule(RuleConfig.Rule rule, NormalizedEvent e) {
    var tags = new LinkedHashMap<>(e.tags());
    var attrs = new LinkedHashMap<>(e.attributes());
    
    if (rule.set().tags() != null) {
      for (Map.Entry<String, String> entry : rule.set().tags().entrySet()) {
        String value = resolveValue(entry.getValue(), e);
        tags.put(entry.getKey(), value);
      }
    }

    Severity severity = e.severity();
    if (rule.set().severity() != null) {
      severity = Severity.valueOf(rule.set().severity());
    }

    return NormalizedEvent.builder()
      .id(e.id()).ts(e.ts()).receivedTs(e.receivedTs())
      .protocol(e.protocol()).kind(e.kind()).source(e.source())
      .pluginId(e.pluginId()).tenant(e.tenant())
      .severity(severity)
      .body(e.body()).tags(tags).attributes(attrs).bytes(e.bytes())
      .build();
  }

  private String resolveValue(String template, NormalizedEvent e) {
    if (template.startsWith("${") && template.endsWith("}")) {
      String path = template.substring(2, template.length() - 1);
      if (path.startsWith("source.")) {
        String field = path.substring(7);
        return switch (field) {
          case "ip" -> e.source().host();
          case "host" -> e.source().host();
          default -> template;
        };
      } else if (path.startsWith("attributes.")) {
        String attrPath = path.substring(11);
        Object value = e.attributes().get(attrPath);
        return value != null ? String.valueOf(value) : "";
      } else {
        Object value = e.attributes().get(path);
        return value != null ? String.valueOf(value) : "";
      }
    }
    return template;
  }
}
