package com.example.springsecurityjwt.dto;

import com.example.springsecurityjwt.entity.Role;
import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String email;
    private String password;
    private Role role;
}
