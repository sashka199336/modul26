package com.globus.modul26.dto;

public class RegisterResponse {
    private Long id;
    private String username;
    private String email; // маскированный!
    private String firstName;
    private String lastName;
    private String phone;
    private String role;


    public RegisterResponse() {}

    // Конструктор
    public RegisterResponse(
            Long id,
            String username,
            String email,
            String firstName,
            String lastName,
            String phone,
            String role
    ) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.phone = phone;
        this.role = role;
    }

    //
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }

    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }

    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}