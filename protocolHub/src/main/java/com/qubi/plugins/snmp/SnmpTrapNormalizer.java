// plugins/snmp/SnmpTrapNormalizer.java
package com.qubi.plugins.snmp;
import com.qubi.core.model.NormalizedEvent;
import com.qubi.core.model.Severity;
import com.qubi.core.spi.EventNormalizer;

public class SnmpTrapNormalizer implements EventNormalizer {
  private static final String TRAP_OID_KEY = "snmp.varbinds.1.3.6.1.6.3.1.1.4.1.0";
  private static final String LINK_DOWN = "1.3.6.1.6.3.1.1.5.3";

  @Override public boolean supports(NormalizedEvent e) {
    return "snmp4j-trap".equals(e.pluginId()); // o e.protocol()==Protocol.SNMP_TRAP
  }

  @Override public NormalizedEvent normalize(NormalizedEvent e) {
    Object trapOid = e.attributes().get(TRAP_OID_KEY);
    if (LINK_DOWN.equals(String.valueOf(trapOid))) {
      var tags = new java.util.LinkedHashMap<>(e.tags());
      var attrs = new java.util.LinkedHashMap<>(e.attributes());
      tags.putIfAbsent("device", e.source().host());
      // ifIndex por OID clásico:
      Object ifIndex = e.attributes().get("snmp.varbinds.1.3.6.1.2.1.2.2.1.1");
      if (ifIndex != null) tags.put("ifIndex", String.valueOf(ifIndex));
      return NormalizedEvent.builder()
        .id(e.id()).ts(e.ts()).receivedTs(e.receivedTs())
        .protocol(e.protocol()).kind(e.kind()).source(e.source())
        .pluginId(e.pluginId()).tenant(e.tenant())
        .severity(Severity.ERROR)
        .body(e.body()).tags(tags).attributes(attrs).bytes(e.bytes())
        .build();
    }
    return e;
  }
}
