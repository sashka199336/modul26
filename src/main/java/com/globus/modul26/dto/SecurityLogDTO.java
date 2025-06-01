package com.globus.modul26.dto;

import java.util.Map;

public class SecurityLogDTO {
    private Long userId;
    private String eventType;
    private String ipAddress;
    private String deviceInfo;
    private Boolean biometryUsed; // Лучше Boolean, чтобы был null, если клиент не прислал
    private Map<String, Object> metadata; // КЛИЕНТ присылает country и city!


    public Long getUserId() {
        return userId;
    }
    public void setUserId(Long userId) {
        this.userId = userId;
    }
    public String getEventType() {
        return eventType;
    }
    public void setEventType(String eventType) {
        this.eventType = eventType;
    }
    public String getIpAddress() {
        return ipAddress;
    }
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    public String getDeviceInfo() {
        return deviceInfo;
    }
    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }
    public Boolean getBiometryUsed() {
        return biometryUsed;
    }
    public void setBiometryUsed(Boolean biometryUsed) {
        this.biometryUsed = biometryUsed;
    }
    public Map<String, Object> getMetadata() {
        return metadata;
    }
    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }
}