package com.globus.modul26.repository;

import com.globus.modul26.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);    // поиск по username
    Optional<User> findByEmail(String email);          // поиск по email
    boolean existsByEmail(String email);
    boolean existsByUsername(String username);


}