// core/runtime/NormalizerRegistry.java
package com.qubi.core.runtime;
import com.qubi.core.model.NormalizedEvent;
import com.qubi.core.spi.EventNormalizer;
import java.util.List;

public class NormalizerRegistry {
  private final List<EventNormalizer> normalizers;
  public NormalizerRegistry(List<EventNormalizer> ns){ this.normalizers = List.copyOf(ns); }
  public NormalizedEvent apply(NormalizedEvent e){
    NormalizedEvent cur = e;
    for (var n : normalizers)
      if (n.supports(cur)) cur = n.normalize(cur);
    return cur;
  }
}
