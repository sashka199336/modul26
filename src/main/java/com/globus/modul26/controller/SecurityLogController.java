package com.globus.modul26.controller;

import com.globus.modul26.model.SecurityLog;
import com.globus.modul26.service.SecurityLogService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@RestController
@RequestMapping("/api/logs")
public class SecurityLogController {

    private final SecurityLogService service;

    public SecurityLogController(SecurityLogService service) {
        this.service = service;
    }

    //  Запись события
    @PostMapping("/event")
    public ResponseEntity<SecurityLog> logEvent(
            @RequestBody SecurityLog log,
            Authentication authentication
    ) {
        // Подстановка userId из токена (из JWT)
        Jwt jwt = (Jwt) authentication.getPrincipal();
        Long userId = Long.parseLong(jwt.getSubject());
        log.setUserId(userId);

        //  Маскировка IP для логов
        if (log.getIpAddress() != null) {
            log.setIpAddress(maskIp(log.getIpAddress()));
        }

        // обраб-отка metadata
        Object metadataRaw = log.getMetadata();
        Map<String, Object> metadataMap;
        if (metadataRaw == null) {
            metadataMap = new HashMap<>();
        } else if (metadataRaw instanceof Map) {
            //noinspection unchecked
            metadataMap = new HashMap<>((Map<String, Object>) metadataRaw);
        } else {
            try {
                com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
                metadataMap = objectMapper.readValue(metadataRaw.toString(), Map.class);
            } catch (Exception e) {
                metadataMap = new HashMap<>();
            }
        }

        //  Маскировка IP
        if (metadataMap.containsKey("ipAddress") && metadataMap.get("ipAddress") instanceof String) {
            String originalIp = (String) metadataMap.get("ipAddress");
            metadataMap.put("ipAddress", maskIp(originalIp));
        }

        // Передаём нормализова
        // ное metadata в лог
        log.setMetadata(metadataMap);


        log.setIsSuspicious(null);

        if (log.getBiometryUsed() == null) {
            log.setBiometryUsed(false);
        }

        SecurityLog saved = service.saveLog(log);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(saved);
    }

    // Получить только подозрител ьные логи по userId
    @GetMapping("/suspicious/{userId}")
    public ResponseEntity<List<SecurityLog>> getSuspiciousByUser(
            @PathVariable Long userId,
            Authentication authentication
    ) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        List<String> rolesList = jwt.getClaimAsStringList("roles");
        boolean isAdmin = rolesList != null && rolesList.contains("ADMIN");
        boolean isUser = rolesList != null && rolesList.contains("USER");

        Long jwtUserId = null;
        try {
            jwtUserId = Long.parseLong(jwt.getSubject());
        } catch (Exception e) {

        }

        if (isAdmin) {
            return ResponseEntity.ok(service.findSuspiciousLogsByUserId(userId));
        }

        if (isUser && jwtUserId != null && jwtUserId.equals(userId)) {
            return ResponseEntity.ok(service.findSuspiciousLogsByUserId(userId));
        }

        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
    }

    // Все логи по пользователя (не только подозрительные)
    @GetMapping("/users/{userId}")
    public ResponseEntity<List<SecurityLog>> getByUser(
            @PathVariable Long userId,
            Authentication authentication
    ) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        List<String> rolesList = jwt.getClaimAsStringList("roles");
        boolean isAdmin = rolesList != null && rolesList.contains("ADMIN");
        boolean isUser = rolesList != null && rolesList.contains("USER");

        Long jwtUserId = null;
        try {
            jwtUserId = Long.parseLong(jwt.getSubject());
        } catch (Exception e) {

        }

        if (isAdmin) {
            return ResponseEntity.ok(service.findByUserId(userId));
        }

        if (isUser && jwtUserId != null && jwtUserId.equals(userId)) {
            return ResponseEntity.ok(service.findByUserId(userId));
        }

        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
    }

    // Маскировка IP, для json-логов и для metadata
    private static String maskIp(String ip) {
        if (ip == null) return null;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return ip;
        String first = parts[0];
        String second = parts[1].isEmpty() ? "*" : parts[1].substring(0, 1);
        String fourth = parts[3];
        // Пример: 192.1**.***.128
        return String.format("%s.%s**.***.%s", first, second, fourth);
    }
}