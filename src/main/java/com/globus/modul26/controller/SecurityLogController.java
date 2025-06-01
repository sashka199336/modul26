package com.globus.modul26.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.globus.modul26.model.SecurityLog;
import com.globus.modul26.service.SecurityLogService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;

@RestController
@RequestMapping("/api/logs")
public class SecurityLogController {

    private final SecurityLogService service;
    private static final ObjectMapper objectMapper = new ObjectMapper();

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
        String maskedIp = maskIp(clientIp);

        // 🛡️ Гарантированная маскировка и защита от null/UNKNOWN/localhost
        if (maskedIp == null || maskedIp.trim().isEmpty() || maskedIp.equals("null") ||
                maskedIp.toLowerCase().contains("unknown") ||
                maskedIp.equals("0:0:0:0:0:0:0:1") || maskedIp.equals("127.0.0.1")) {
            maskedIp = "UNKNOWN";
        }
        log.setIpAddress(maskedIp);

        String deviceInfo = request.getHeader("User-Agent");
        log.setDeviceInfo(deviceInfo);

        String browser = parseBrowser(deviceInfo);
        String platform = parsePlatform(deviceInfo);

        Map<String, String> geo = getGeoDataByIp(clientIp); // JSON-парсер!
        String country = geo.getOrDefault("country", "Unknown");
        String city = geo.getOrDefault("city", "Unknown");

        // Сохраняем метаданные
        Map<String, Object> metadataMap;
        if (log.getMetadata() instanceof Map) {
            metadataMap = new HashMap<>((Map<String, Object>) log.getMetadata());
        } else {
            metadataMap = new HashMap<>();
        }
        metadataMap.put("country", country);
        metadataMap.put("city", city);
        if (!"Unknown".equals(platform)) {
            metadataMap.put("platform", platform);
        }
        if (!"Unknown".equals(browser)) {
            metadataMap.put("browser", browser);
        }
        log.setMetadata(metadataMap);

        log.setIsSuspicious(null);

        if (log.getBiometryUsed() == null) {
            log.setBiometryUsed(false);
        }

        if (log.getIpAddress() == null || log.getIpAddress().trim().isEmpty()) {
            log.setIpAddress("UNKNOWN");
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

    // 🔒 Маскирует IP-адрес
    private static String maskIp(String ip) {
        if (ip == null) return null;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return ip; // если это IPv6 или некорректно, возвращаем как есть
        String first = parts[0];
        String second = parts[1].isEmpty() ? "*" : parts[1].substring(0, 1);
        String fourth = parts[3];
        return String.format("%s.%s**.***.%s", first, second, fourth);
    }

    // 🌐 Получает реальный IP пользователя
    private static String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0];
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr != null && !remoteAddr.isEmpty()) {
            return remoteAddr;
        }
        return "UNKNOWN";
    }

    // 🌍 Правильный парсинг страны и города по IP через ipapi.co с использованием Jackson
    private static Map<String, String> getGeoDataByIp(String ip) {
        Map<String, String> geoData = new HashMap<>();
        try {
            if (ip == null || ip.startsWith("127.") || ip.startsWith("192.168.") ||
                    ip.startsWith("10.") || ip.equals("0:0:0:0:0:0:0:1") ||
                    ip.equalsIgnoreCase("UNKNOWN")) {
                geoData.put("country", "Unknown");
                geoData.put("city", "Unknown");
                return geoData;
            }
            URL url = new URL("https://ipapi.co/" + ip + "/json/");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                String json = response.toString();

                Map<String, Object> map = objectMapper.readValue(json, Map.class);
                String country = map.get("country_name") != null ? map.get("country_name").toString() : "Unknown";
                String city = map.get("city") != null ? map.get("city").toString() : "Unknown";
                geoData.put("country", country);
                geoData.put("city", city);
            }
        } catch (Exception e) {
            geoData.put("country", "Unknown");
            geoData.put("city", "Unknown");
        }
        return geoData;
    }

    // 🖥️ Определение браузера
    private static String parseBrowser(String userAgent) {
        if (userAgent == null) return "Unknown";
        if (userAgent.contains("OPR") || userAgent.contains("Opera")) return "Opera";
        if (userAgent.contains("Edg") || userAgent.contains("Edge")) return "Edge";
        if (userAgent.contains("Chrome")) return "Chrome";
        if (userAgent.contains("Firefox")) return "Firefox";
        if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) return "Safari";
        return "Unknown";
    }

    // 💻 Определение операционной системы
    private static String parsePlatform(String userAgent) {
        if (userAgent == null) return "Unknown";
        if (userAgent.contains("Windows")) return "Windows";
        if (userAgent.contains("Mac OS") || userAgent.contains("Macintosh")) return "Mac";
        if (userAgent.contains("Linux")) return "Linux";
        if (userAgent.contains("Android")) return "Android";
        if (userAgent.contains("iPhone") || userAgent.contains("iPad") || userAgent.contains("iOS")) return "iOS";
        return "Unknown";
    }
}
