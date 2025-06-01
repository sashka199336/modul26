package com.globus.modul26.security;

import com.globus.modul26.model.SecurityLog;
import com.globus.modul26.repository.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

@Component
public class SuspiciousActivityDetector {

    @Autowired
    private SecurityLogRepository logRepository;

    private static final Set<String> BLACKLISTED_COUNTRIES = Set.of("UKR", "USA", "POL");

    /**
     * Вытаскиваем geoLocation как "country,city" из metadata.
     */
    private static String extractGeoLocation(SecurityLog log) {
        Map<String, Object> md = log.getMetadata();
        String country = md != null && md.get("country") != null ? md.get("country").toString() : "";
        String city = md != null && md.get("city") != null ? md.get("city").toString() : "";
        return country + "," + city;
    }

    public void analyze(SecurityLog log) {
        Long userId = log.getUserId();

        //  IP
        if (isNewIp(userId, log.getIpAddress())) {
            System.out.println("Вход с нового IP: " + log.getIpAddress());
        }

        //  GEO
        String geoLocation = extractGeoLocation(log);

        if (isNewGeo(userId, geoLocation)) {
            System.out.println("Вход с новой геолокации: " + geoLocation);
        }

        //  Device
        if (isNewDevice(userId, log.getDeviceInfo())) {
            System.out.println("Вход с нового устройства: " + log.getDeviceInfo());
        }


        if (hasTooManyFailedAttempts(userId)) {
            System.out.println("Частые неудачные попытки входа!");
        }


        if (hasTooManyPasswordChanges(userId)) {
            System.out.println("Множественные смены пароля за короткое время!");
        }


        if (isLoginWithoutBiometryWhereWasBiometryBefore(userId, log)) {
            System.out.println("Попытка входа с устройства без биометрии, где раньше использовалась биометрия!");
        }


        if (isBlacklistedCountry(geoLocation)) {
            System.out.println("Активность из страны из чёрного списка!");
        }


        if (isUserAgentMismatch(userId, log.getDeviceInfo())) {
            System.out.println("Несоответствие User-Agent между сессиями!");
        }
    }

    private boolean isNewIp(Long userId, String currentIp) {
        List<SecurityLog> logs = logRepository.findByUserId(userId);
        return logs.stream().noneMatch(log -> currentIp.equals(log.getIpAddress()));
    }

    private boolean isNewGeo(Long userId, String currentGeo) {
        if (currentGeo == null) return false;
        List<SecurityLog> logs = logRepository.findByUserId(userId);
        for (SecurityLog log : logs) {
            String logGeo = extractGeoLocation(log);
            if (currentGeo.equals(logGeo)) {
                return false;
            }
        }
        return true;
    }

    private boolean isNewDevice(Long userId, String currentDevice) {
        if (currentDevice == null) return false;
        List<SecurityLog> logs = logRepository.findByUserId(userId);
        return logs.stream().noneMatch(log -> currentDevice.equals(log.getDeviceInfo()));
    }

    private boolean hasTooManyFailedAttempts(Long userId) {
        LocalDateTime fiveMinsAgo = LocalDateTime.now().minusMinutes(5);
        List<SecurityLog> logs =
                logRepository.findByUserIdAndIsSuspiciousAndCreatedAtAfter(userId, false, fiveMinsAgo);
        return logs.size() > 3;
    }

    private boolean hasTooManyPasswordChanges(Long userId) {
        LocalDateTime dayAgo = LocalDateTime.now().minusDays(1);
        List<SecurityLog> logs =
                logRepository.findByUserIdAndEventTypeAndCreatedAtAfter(userId, "PASSWORD_CHANGE", dayAgo);
        return logs.size() > 2;
    }

    private boolean isLoginWithoutBiometryWhereWasBiometryBefore(Long userId, SecurityLog log) {
        if (!"LOGIN".equals(log.getEventType()) || Boolean.TRUE.equals(log.getBiometryUsed())) return false;
        List<SecurityLog> logs = logRepository.findByUserIdAndBiometryUsed(userId, true);
        return !logs.isEmpty();
    }

    private boolean isBlacklistedCountry(String geoLocation) {
        if (geoLocation == null) return false;
        String country = geoLocation.split(",")[0].trim();
        return BLACKLISTED_COUNTRIES.contains(country);
    }

    private boolean isUserAgentMismatch(Long userId, String currentDeviceInfo) {
        List<SecurityLog> logs = logRepository.findByUserId(userId);
        Set<String> agents = new HashSet<>();
        for (SecurityLog log : logs) {
            agents.add(log.getDeviceInfo());
        }
        return agents.size() > 1 && !agents.contains(currentDeviceInfo);
    }
}