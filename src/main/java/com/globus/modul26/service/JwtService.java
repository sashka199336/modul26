package com.globus.modul26.service;

import com.globus.modul26.model.User;

public interface JwtService {
    String generateToken(User user);
}