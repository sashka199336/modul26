package com.globus.modul26.controller;

import com.globus.modul26.model.Role;
import com.globus.modul26.model.User;
import com.globus.modul26.repository.UserRepository;
import com.globus.modul26.dto.RegisterRequest;
import com.globus.modul26.dto.RegisterResponse;
import com.globus.modul26.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/auth")
public class RegistrationController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public RegistrationController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest req) {
        // Проверка обязательных полей
        if (req.getUsername() == null || req.getUsername().isBlank() ||
                req.getPassword() == null || req.getPassword().isBlank() ||
                req.getEmail() == null || req.getEmail().isBlank() ||
                req.getFirstName() == null || req.getFirstName().isBlank() ||
                req.getLastName() == null || req.getLastName().isBlank() ||
                req.getRole() == null || req.getRole().isBlank()) {
            return ResponseEntity.badRequest().body("Заполните все обязательные поля");
        }

        // Проверка email на уникальность
        if (userRepository.existsByEmail(req.getEmail())) {
            return ResponseEntity.badRequest().body("Email уже используется");
        }

        // Проверка username на уникальность
        if (userRepository.existsByUsername(req.getUsername())) {
            return ResponseEntity.badRequest().body("Username уже используется");
        }

        // Конверсия роли из String в Enum
        Role userRole;
        try {
            userRole = Role.valueOf(req.getRole());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Некорректная роль: " + req.getRole());
        }

        // Создаеие пользователя
        User user = new User();
        user.setUsername(req.getUsername());
        user.setEmail(req.getEmail());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setFirstName(req.getFirstName());
        user.setLastName(req.getLastName());
        user.setPhone(req.getPhone());
        user.setRole(userRole);
        user.setCreatedAt(LocalDateTime.now());

        userRepository.save(user);

        // Генерирация токена
        String jwtToken = jwtService.generateToken(user);

        // Маскировка email
        String maskedEmail = maskEmail(user.getEmail());

        // Формирование ОТВЕТа :
        RegisterResponse response = new RegisterResponse(
                user.getId(),
                user.getUsername(),
                maskedEmail,
                user.getFirstName(),
                user.getLastName(),
                user.getPhone(),
                user.getRole().toString()


        );

        return ResponseEntity.ok(response);
    }

    // --- Утилита для маскировки email ---
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return email;
        String[] parts = email.split("@");
        String name = parts[0];
        String domain = parts[1];
        String maskedName = name.length() <= 2 ? name + "**" : name.substring(0, 2) + "**";
        int dotIndex = domain.indexOf('.');
        String domainName = dotIndex > 0 ? domain.substring(0, dotIndex) : domain;
        String domainZone = dotIndex > 0 ? domain.substring(dotIndex) : "";
        String maskedDomain = domainName.length() <= 2
                ? domainName + "****"
                : domainName.substring(0, 2) + "****";
        return maskedName + "@" + maskedDomain + domainZone;
    }
}