package com.globus.modul26.controller;

import com.globus.modul26.model.SecurityLog;
import com.globus.modul26.service.SecurityLogService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest; // <-- только это!
import java.util.*;

@RestController
@RequestMapping("/api/logs")
public class SecurityLogController {

    private final SecurityLogService service;

    public SecurityLogController(SecurityLogService service) {
        this.service = service;
    }

    @PostMapping("/event")
    public ResponseEntity<SecurityLog> logEvent(
            @RequestBody SecurityLog log,
            Authentication authentication,
            HttpServletRequest request
    ) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        Long userId = Long.parseLong(jwt.getSubject());
        log.setUserId(userId);

        String clientIp = getClientIp(request);
        log.setIpAddress(maskIp(clientIp));

        String deviceInfo = request.getHeader("User-Agent");
        log.setDeviceInfo(deviceInfo);

        Map<String, Object> metadataMap = log.getMetadata() instanceof Map ?
                new HashMap<>((Map) log.getMetadata()) : new HashMap<>();

        String country = "Unknown";
        String city = "Unknown";
        String browser = parseBrowser(deviceInfo);
        String platform = parsePlatform(deviceInfo);

        metadataMap.put("country", country);
        metadataMap.put("city", city);
        metadataMap.put("platform", platform);
        metadataMap.put("browser", browser);

        log.setMetadata(metadataMap);

        log.setIsSuspicious(null);

        if (log.getBiometryUsed() == null) {
            log.setBiometryUsed(false);
        }

        SecurityLog saved = service.saveLog(log);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

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
        } catch (Exception ignored) {}

        if (isAdmin || (isUser && Objects.equals(jwtUserId, userId))) {
            return ResponseEntity.ok(service.findSuspiciousLogsByUserId(userId));
        }
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
    }

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
        } catch (Exception ignored) {}

        if (isAdmin || (isUser && Objects.equals(jwtUserId, userId))) {
            return ResponseEntity.ok(service.findByUserId(userId));
        }
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied");
    }

    private static String maskIp(String ip) {
        if (ip == null) return null;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return ip;
        String first = parts[0];
        String second = parts[1].isEmpty() ? "*" : parts[1].substring(0, 1);
        String fourth = parts[3];
        return String.format("%s.%s**.***.%s", first, second, fourth);
    }

    // Используем jakarta.servlet.http.HttpServletRequest!
    private static String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0];
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    private static String parseBrowser(String userAgent) {
        if (userAgent == null) return "Unknown";
        if (userAgent.contains("Chrome")) return "Chrome";
        if (userAgent.contains("Firefox")) return "Firefox";
        if (userAgent.contains("Safari")) return "Safari";
        return "Unknown";
    }

    private static String parsePlatform(String userAgent) {
        if (userAgent == null) return "Unknown";
        if (userAgent.contains("Windows")) return "Windows";
        if (userAgent.contains("Mac OS")) return "Mac";
        if (userAgent.contains("Linux")) return "Linux";
        if (userAgent.contains("Android")) return "Android";
        if (userAgent.contains("iPhone")) return "iOS";
        return "Unknown";
    }
}
