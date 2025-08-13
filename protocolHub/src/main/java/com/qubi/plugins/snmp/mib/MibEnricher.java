// com.qubi.plugins.snmp.mib.MibEnricher.java
package com.qubi.plugins.snmp.mib;

import java.util.Map;

public interface MibEnricher {
  /** Devuelve un mapa con nombres y valores “bonitos” además de los OIDs crudos. */
  Map<String,Object> enrich(Map<String,Object> rawVarbinds);
}
