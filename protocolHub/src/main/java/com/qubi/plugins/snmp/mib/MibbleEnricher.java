package com.qubi.plugins.snmp.mib;

import net.percederberg.mibble.Mib;
import net.percederberg.mibble.MibLoader;
import net.percederberg.mibble.MibSymbol;
import net.percederberg.mibble.value.ObjectIdentifierValue;

import java.io.File;
import java.util.*;

public class MibbleEnricher implements MibEnricher {

  private final List<Mib> loaded = new ArrayList<>();

  /** mibsDir: carpeta con .mib; modules: nombres de módulos (ej: "IF-MIB", "SNMPv2-MIB") */
  public MibbleEnricher(File mibsDir, List<String> modules) throws Exception {
    MibLoader loader = new MibLoader();
    if (mibsDir != null) {
      loader.addDir(mibsDir);
      // También estas dos, donde suelen estar SNMPv2-* y otras dependencias
      File ietf = new File(mibsDir, "ietf");
      File iana = new File(mibsDir, "iana");
      if (ietf.isDirectory()) loader.addDir(ietf);
      if (iana.isDirectory()) loader.addDir(iana);
    }

    for (String mod : modules) {
      try {
        loaded.add(loader.load(mod));
        System.out.println("[MIBBLE] Loaded module: " + mod);
      } catch (Exception ex) {
        System.err.println("[MIBBLE] FAILED to load module: " + mod + " -> " + ex.getMessage());
        throw ex; // o continuá si querés best-effort
      }
    }
  }

  @Override
  public Map<String, Object> enrich(Map<String, Object> raw) {
    Map<String, Object> out = new LinkedHashMap<>(raw);
    for (var e : new ArrayList<>(raw.entrySet())) {
      String oidStr = e.getKey();
      Object val = e.getValue();
      try {
        ObjectIdentifierValue oid = new ObjectIdentifierValue(oidStr,-1);
        MibSymbol sym = resolve(oid);
        if (sym != null) {
          String fq = sym.getName() + "::" + sym.getName();
          out.put(fq, val);                      // alias legible
          out.put("mib.name." + oidStr, fq);     // mapping OID -> nombre
        }
      } catch (Exception ignore) {
        // Si no es un OID válido o no se puede resolver, lo dejamos tal cual
      }
    }
    return out;
  }

  private MibSymbol resolve(ObjectIdentifierValue oid) {
    for (Mib m : loaded) {
      try {
        MibSymbol s = m.getSymbolByValue(oid);
        if (s != null) return s;
      } catch (Exception ignored) {}
    }
    return null;
  }
}
