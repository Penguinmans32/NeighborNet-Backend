package com.example.neighbornetbackend.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@RequestMapping("/api/test")
@RestController
public class TestController {

    @GetMapping("/public")
    public ResponseEntity<?> publicAccess() {
        return ResponseEntity.ok("This is public endpoint");
    }

    @GetMapping("/user")
    public ResponseEntity<?> userAccess() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        String formatDateTime = now.format(formatter);

        Map<String, String> response = new HashMap<>();
        response.put("message", "This is user endpoint");
        response.put("username", auth.getName());
        response.put("time", formatDateTime);
        response.put("status", "authenticated");

        return ResponseEntity.ok(response);
    }
}
