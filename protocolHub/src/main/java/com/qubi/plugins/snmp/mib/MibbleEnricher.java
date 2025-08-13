package com.qubi.plugins.snmp.mib;

import net.percederberg.mibble.Mib;
import net.percederberg.mibble.MibLoader;
import net.percederberg.mibble.MibSymbol;
import net.percederberg.mibble.MibValueSymbol;
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
        MibSymbol sym = findSymbolByOidString(oidStr);
        if (sym != null) {
          String fq = sym.getMib().getName() + "::" + sym.getName();
          out.put(fq, val);                      // alias legible
          out.put("mib.name." + oidStr, fq);     // mapping OID -> nombre
        }
      } catch (Exception ignore) {
        // Si no es un OID válido o no se puede resolver, lo dejamos tal cual
      }
    }
    return out;
  }

  private MibSymbol findSymbolByOidString(String oidStr) {
    if (oidStr == null || oidStr.trim().isEmpty()) {
      return null;
    }
    
    for (Mib mib : loaded) {
      Collection<MibSymbol> symbols = mib.getAllSymbols();
      for (MibSymbol symbol : symbols) {
        if (symbol instanceof MibValueSymbol valueSymbol) {
          if (valueSymbol.getValue() instanceof ObjectIdentifierValue oidValue) {
            String symbolOidStr = oidValue.toString();
            if (oidStr.equals(symbolOidStr)) {
              return symbol;
            }
          }
        }
      }
    }
    return null;
  }
}
