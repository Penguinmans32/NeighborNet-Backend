package com.example.neighbornetbackend.dto;


public class AuthResponse {
    private String token;
    private String refreshToken;
    private String type = "Bearer";
    private String username;

    public AuthResponse(String token, String refreshToken, String type, String username) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.type = type;
        this.username = username;
    }


    // Getters and Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
