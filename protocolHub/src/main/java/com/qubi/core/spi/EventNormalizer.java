// core/spi/EventNormalizer.java
package com.qubi.core.spi;
import com.qubi.core.model.NormalizedEvent;

public interface EventNormalizer {
  /** ¿Este normalizador aplica para este evento? (p.ej. por pluginId o protocol) */
  boolean supports(NormalizedEvent e);
  /** Devuelve el evento enriquecido (o el mismo si no cambia). */
  NormalizedEvent normalize(NormalizedEvent e);
}
