package com.globus.modul26.service;

import com.globus.modul26.model.SecurityLog;
import com.globus.modul26.repository.SecurityLogRepository;
import com.globus.modul26.util.CefUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class SecurityLogServiceImpl implements SecurityLogService {

    private final SecurityLogRepository repository;
    private static final Set<String> BLACKLISTED_COUNTRIES = Set.of(
            "USA", "UKR", "POL"
    );
    private static final Logger cefLogger = LoggerFactory.getLogger("cefLogger");

    public SecurityLogServiceImpl(SecurityLogRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public void logEvent(Long userId, String eventType, String ipAddress, String deviceInfo, Boolean biometryUsed) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("country", "UNKNOWN");
        metadata.put("city", "UNKNOWN");

        SecurityLog log = SecurityLog.builder()
                .userId(userId)
                .eventType(eventType)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .metadata(metadata)
                .biometryUsed(biometryUsed)
                .createdAt(LocalDateTime.now())
                .build();

        saveLog(log);
    }

    @Transactional
    public void logLoginAttempt(Long userId, String ipAddress, String deviceInfo, boolean success) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("country", "UNKNOWN");
        metadata.put("city", "UNKNOWN");

        SecurityLog log = SecurityLog.builder()
                .userId(userId)
                .eventType("LOGIN_ATTEMPT")
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .metadata(metadata)
                .biometryUsed(false)
                .createdAt(LocalDateTime.now())
                .isSuspicious(!success)
                .build();

        saveLog(log);
    }

    @Override
    @Transactional
    public SecurityLog saveLog(SecurityLog log) {
        // 🛡️ Не даём null/ip пустыми в базу!
        if (log.getIpAddress() == null || log.getIpAddress().trim().isEmpty()
                || "null".equalsIgnoreCase(log.getIpAddress())
                || "127.0.0.1".equals(log.getIpAddress())
                || "0:0:0:0:0:0:0:1".equals(log.getIpAddress())) {
            log.setIpAddress("UNKNOWN");
        }

        if (log.getCreatedAt() == null) {
            log.setCreatedAt(LocalDateTime.now());
        }

        if (log.getMetadata() == null) {
            log.setMetadata(new HashMap<>());
        }
        if (!log.getMetadata().containsKey("country")) {
            log.getMetadata().put("country", "UNKNOWN");
        }
        if (!log.getMetadata().containsKey("city")) {
            log.getMetadata().put("city", "UNKNOWN");
        }

        if (log.getIsSuspicious() == null) {
            log.setIsSuspicious(isSuspicious(log));
        }

        SecurityLog saved = repository.save(log);

        if (Boolean.TRUE.equals(saved.getIsSuspicious())) {
            Map<String, String> extension = new HashMap<>();
            extension.put("userId", String.valueOf(saved.getUserId()));
            extension.put("eventType", saved.getEventType());
            extension.put("ip", saved.getIpAddress());

            if (saved.getDeviceInfo() != null)
                extension.put("device_info", saved.getDeviceInfo());

            if (saved.getBiometryUsed() != null)
                extension.put("biometry", saved.getBiometryUsed().toString());

            extension.put("isSuspicious", String.valueOf(saved.getIsSuspicious()));
            extension.put("country", saved.getMetadata().get("country").toString());
            extension.put("city", saved.getMetadata().get("city").toString());

            String cefLog = CefUtil.toCef(
                    "1001",
                    saved.getEventType(),
                    8,
                    extension
            );
            cefLogger.info(cefLog);
        }
        return saved;
    }

    @Override
    public boolean isNewIp(Long userId, String currentIp) {
        if (currentIp == null) return false;
        List<SecurityLog> logs = repository.findByUserId(userId);
        return logs.stream().noneMatch(log -> currentIp.equals(log.getIpAddress()));
    }

    @Override
    public boolean isNewGeo(Long userId, String currentGeoLocation) {
        if (currentGeoLocation == null) return false;
        String[] parts = currentGeoLocation.split(",");
        if (parts.length < 2) return false;
        String country = parts[0].trim();
        String city = parts[1].trim();
        List<SecurityLog> logs = repository.findByUserId(userId);
        return logs.stream().noneMatch(log -> {
            Map<String, Object> md = log.getMetadata();
            return md != null
                    && country.equals(md.get("country"))
                    && city.equals(md.get("city"));
        });
    }

    @Override
    public boolean isNewDevice(Long userId, String currentDeviceInfo) {
        if (currentDeviceInfo == null) return false;
        List<SecurityLog> logs = repository.findByUserId(userId);
        return logs.stream().noneMatch(log ->
                currentDeviceInfo.equals(log.getDeviceInfo())
        );
    }

    @Override
    public boolean hasTooManyFailedAttempts(Long userId) {
        int BLOCK_LIMIT = 3;
        List<SecurityLog> lastAttempts = repository.findTop3ByUserIdAndEventTypeOrderByCreatedAtDesc(userId, "LOGIN_ATTEMPT");
        if (lastAttempts.size() < BLOCK_LIMIT) return false;
        return lastAttempts.stream().allMatch(log -> Boolean.TRUE.equals(log.getIsSuspicious()));
    }

    @Override
    public boolean hasTooManyPasswordChanges(Long userId) {
        LocalDateTime dayAgo = LocalDateTime.now().minusDays(1);
        List<SecurityLog> logs =
                repository.findByUserIdAndEventTypeAndCreatedAtAfter(userId, "PASSWORD_CHANGE", dayAgo);
        return logs.size() > 2;
    }

    @Override
    public boolean isLoginWithoutBiometryWhereWasBiometryBefore(Long userId, SecurityLog log) {
        if (!"LOGIN".equals(log.getEventType()) || Boolean.TRUE.equals(log.getBiometryUsed()))
            return false;
        List<SecurityLog> logs = repository.findByUserIdAndBiometryUsed(userId, true);
        return !logs.isEmpty();
    }

    @Override
    public boolean isBlacklistedCountry(String geoLocation) {
        if (geoLocation == null) return false;
        String country = geoLocation.split(",")[0].trim();
        return BLACKLISTED_COUNTRIES.contains(country.toUpperCase());
    }

    @Override
    public boolean isUserAgentMismatch(Long userId, String currentDeviceInfo) {
        List<SecurityLog> logs = repository.findByUserId(userId);
        Set<String> agents = new HashSet<>();
        for (SecurityLog log : logs) {
            String di = log.getDeviceInfo();
            if (di != null) agents.add(di);
        }
        return agents.size() > 1 && !agents.contains(currentDeviceInfo);
    }

    @Override
    public List<SecurityLog> findSuspiciousLogs() {
        List<SecurityLog> allLogs = repository.findAll();
        List<SecurityLog> result = new ArrayList<>();
        for (SecurityLog log : allLogs) {
            if (isSuspicious(log)) {
                result.add(log);
            }
        }
        return result;
    }

    @Override
    public List<SecurityLog> getLastLoginAttempts(Long userId, int limit) {
        return repository.findTop3ByUserIdAndEventTypeOrderByCreatedAtDesc(userId, "LOGIN_ATTEMPT");
    }

    @Override
    public List<SecurityLog> findSuspiciousLogsByUserId(Long userId) {
        List<SecurityLog> userLogs = repository.findByUserId(userId);
        List<SecurityLog> suspicious = new ArrayList<>();
        for (SecurityLog log : userLogs) {
            if (isSuspicious(log)) {
                suspicious.add(log);
            }
        }
        return suspicious;
    }

    @Override
    public List<SecurityLog> findByUserId(Long userId) {
        return repository.findByUserId(userId);
    }

    // --- Вспомогательная логика --------------------------------------------------------------------------------------
    private boolean isSuspicious(SecurityLog log) {
        if ("LOGIN_ATTEMPT".equals(log.getEventType())) {
            return Boolean.TRUE.equals(log.getIsSuspicious());
        }

        Long userId = log.getUserId();
        if (userId == null) return false;

        if ("LOGIN".equals(log.getEventType()) && !Boolean.TRUE.equals(log.getBiometryUsed())) {
            return true;
        }

        Map<String, Object> md = log.getMetadata();
        String country = md != null && md.get("country") != null ? md.get("country").toString() : "";
        String city = md != null && md.get("city") != null ? md.get("city").toString() : "";
        String geoString = country + "," + city;

        String deviceInfo = log.getDeviceInfo();
        boolean suspiciousDevice = isNewDevice(userId, deviceInfo);

        String platform = md != null && md.get("platform") != null ? md.get("platform").toString() : "";
        String browser  = md != null && md.get("browser")  != null ? md.get("browser").toString()  : "";

        boolean suspiciousPlatformBrowser = false;
        if (!platform.isEmpty() || !browser.isEmpty()) {
            List<SecurityLog> logs = repository.findByUserId(userId);
            suspiciousPlatformBrowser = logs.stream().noneMatch(oldLog -> {
                Map<String, Object> oldMd = oldLog.getMetadata();
                if (oldMd == null) return false;
                String oldPlatform = oldMd.get("platform") != null ? oldMd.get("platform").toString() : "";
                String oldBrowser  = oldMd.get("browser")  != null ? oldMd.get("browser").toString() : "";
                return platform.equals(oldPlatform) && browser.equals(oldBrowser);
            });
        }

        // -- Сигналы подозрительности --
        if (isNewIp(userId, log.getIpAddress())) return true;
        if (isNewGeo(userId, geoString)) return true;
        if (suspiciousDevice) return true;
        if (suspiciousPlatformBrowser) return true;
        if (hasTooManyFailedAttempts(userId)) return true;
        if (hasTooManyPasswordChanges(userId)) return true;
        if (isLoginWithoutBiometryWhereWasBiometryBefore(userId, log)) return true;
        if (isBlacklistedCountry(geoString)) return true;
        if (isUserAgentMismatch(userId, deviceInfo)) return true;

        // Если ничего не сработало — лог не подозрительный
        return false;
    }
}
