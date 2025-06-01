package com.globus.modul26.controller;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.Date;
import java.util.List;
import java.time.LocalDateTime;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import com.globus.modul26.model.User;
import com.globus.modul26.model.SecurityLog;
import com.globus.modul26.repository.UserRepository;
import com.globus.modul26.service.SecurityLogService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String SECRET = "super-secure-random-string-change-me-please-super-long";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityLogService securityLogService;

    @Autowired
    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          SecurityLogService securityLogService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.securityLogService = securityLogService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest login, HttpServletRequest request) {
        Optional<User> userOpt = userRepository.findByUsername(login.getUsername());
        Long userId = userOpt.map(User::getId).orElse(null);

        //  Проверка блокировкИ пользо вателя
        if (userOpt.isPresent() && Boolean.TRUE.equals(userOpt.get().getLocked())) {
            // Логируем попытку входа для уже заблокированного юзера
            securityLogService.saveLog(SecurityLog.builder()
                    .userId(userId)
                    .eventType("LOGIN_ATTEMPT")
                    .ipAddress(request.getRemoteAddr())
                    .isSuspicious(true)
                    .deviceInfo(request.getHeader("User-Agent"))
                    .createdAt(LocalDateTime.now())
                    .build()
            );
            return ResponseEntity.status(403).body("Пользователь заблокирован из-за многократных неудачных попыток входа");
        }

        boolean success = userOpt.isPresent()
                && passwordEncoder.matches(login.getPassword(), userOpt.get().getPassword());

        //  Логироваан попытку входа
        securityLogService.saveLog(SecurityLog.builder()
                .userId(userId)
                .eventType("LOGIN_ATTEMPT")
                .ipAddress(request.getRemoteAddr())
                .isSuspicious(!success)  // true - если неудачная попытка
                .deviceInfo(request.getHeader("User-Agent"))
                .createdAt(LocalDateTime.now())
                .build()
        );

        // 3. Если не успех — блок
        if (!success) {
            if (userOpt.isPresent()) {
                User user = userOpt.get();

                // 3 попытки входа для пользователя
                List<SecurityLog> lastAttempts = securityLogService.getLastLoginAttempts(user.getId(), 3);

                // пПРОВЕРКА все ли последниХ 3  ПОПЫТОК
                boolean lastThreeFailed = lastAttempts.size() == 3 &&
                        lastAttempts.stream().allMatch(SecurityLog::getIsSuspicious);

                if (lastThreeFailed) {
                    user.setLocked(true);
                    userRepository.save(user);
                    return ResponseEntity.status(403)
                            .body("Пользователь заблокирован из-за 3 неудачных попыток входа подряд");
                }
            }
            return ResponseEntity.status(401).body("Неверный логин или пароль");
        }

        //  Если ок — обновляение время последнего входа
        User user = userOpt.get();
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        String token = Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("roles", List.of(user.getRole().name()))
                .claim("email", user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                .signWith(SignatureAlgorithm.HS256, SECRET.getBytes())
                .compact();

        return ResponseEntity.ok(new JwtResponse(token));
    }

    // DTO для логина
    static class LoginRequest {
        private String username;
        private String password;
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    // DTO для ответа с токеном
    static class JwtResponse {
        private String token;
        public JwtResponse(String token) { this.token = token; }
        public String getToken() { return token; }
    }
}