package com.qubi.core.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public final class JsonSupport {
    private JsonSupport(){}
    public static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

    public static byte[] toBytes(Object o){
        try { return MAPPER.writeValueAsBytes(o); }
        catch (JsonProcessingException e){ throw new RuntimeException(e); }
    }
    public static <T> T fromBytes(byte[] b, Class<T> cls){
        try { return MAPPER.readValue(b, cls); }
        catch (Exception e){ throw new RuntimeException(e); }
    }
}
