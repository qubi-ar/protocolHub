// plugins/syslog/SyslogEventNormalizer.java
package com.qubi.plugins;
import com.qubi.core.model.NormalizedEvent;
import com.qubi.core.model.Severity;
import com.qubi.core.spi.EventNormalizer;
import java.util.Map;
import java.util.regex.*;

public class SyslogEventNormalizer implements EventNormalizer {
  private static final Pattern CPU = Pattern.compile("(?i)cpu[:=]\\s*(?<pct>\\d{1,3})%");

  @Override public boolean supports(NormalizedEvent e) {
    return "syslog-udp".equals(e.pluginId()); // o e.protocol()==Protocol.SYSLOG
  }

  @Override public NormalizedEvent normalize(NormalizedEvent e) {
    if (e.body()==null) return e;
    var m = CPU.matcher(e.body());
    if (m.find()) {
      var tags = new java.util.LinkedHashMap<>(e.tags());
      var attrs = new java.util.LinkedHashMap<>(e.attributes());
      attrs.put("syslog.cpu_pct", m.group("pct"));
      return NormalizedEvent.builder()
        .id(e.id()).ts(e.ts()).receivedTs(e.receivedTs())
        .protocol(e.protocol()).kind(e.kind()).source(e.source())
        .pluginId(e.pluginId()).tenant(e.tenant())
        .severity(e.severity()!=null? e.severity(): Severity.WARN)
        .body(e.body()).tags(tags).attributes(attrs).bytes(e.bytes())
        .build();
    }
    return e;
  }
}
