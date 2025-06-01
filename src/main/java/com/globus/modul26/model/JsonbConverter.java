package com.globus.modul26.model;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.postgresql.util.PGobject;
import java.util.Map;

@Converter(autoApply = false)
public class JsonbConverter implements AttributeConverter<Map<String, Object>, Object> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Object convertToDatabaseColumn(Map<String, Object> attribute) {
        if (attribute == null) return null;
        try {
            PGobject pgObject = new PGobject();
            pgObject.setType("jsonb");
            pgObject.setValue(objectMapper.writeValueAsString(attribute));
            return pgObject;
        } catch (Exception e) {
            throw new IllegalArgumentException("Ошибка сериализации metadata", e);
        }
    }

    @Override
    public Map<String, Object> convertToEntityAttribute(Object dbData) {
        if (dbData == null) return null;
        try {
            String json;
            if (dbData instanceof PGobject) {
                json = ((PGobject) dbData).getValue();
            } else {
                json = dbData.toString();
            }
            return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Ошибка десериализации metadata", e);
        }
    }
}