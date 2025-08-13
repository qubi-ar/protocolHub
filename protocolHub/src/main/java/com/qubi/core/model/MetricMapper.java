package com.qubi.core.model;

import java.util.List;

public interface MetricMapper {
    List<MetricPoint> map(NormalizedEvent e);
}
