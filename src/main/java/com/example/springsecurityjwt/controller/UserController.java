package com.example.springsecurityjwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/users/profile")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public String userProfile(Authentication authentication) {
        return "Hello " + authentication.getName() + ", this is your profile.";
    }

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminDashboard(Authentication authentication) {
        return "Welcome " + authentication.getName() + " to admin dashboard.";
    }
}
