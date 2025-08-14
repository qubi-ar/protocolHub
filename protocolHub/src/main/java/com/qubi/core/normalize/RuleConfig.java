package com.qubi.core.normalize;

import java.util.List;
import java.util.Map;

public record RuleConfig(List<Rule> rules, String trap_oid_key) {



    public record Rule(
        Match match,
        SetOp set
    ){}
    public record Match(
        String protocol,        // "SYSLOG" | "SNMP_TRAP" | ...
        String body_regex,      // opcional
        String trap_oid         // opcional (para SNMP)
    ){}
    public record SetOp(
        Map<String,String> tags,
        Map<String,String> attributes,
        String severity        // "INFO"|"WARN"|...
    ){}
}
