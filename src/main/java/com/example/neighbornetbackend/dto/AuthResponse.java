package com.example.neighbornetbackend.dto;


public class AuthResponse {
    private String token;
    private String type = "Bearer";
    private String username;

    public AuthResponse(String jwt, String bearer, String username) {
        this.token = jwt;
        this.type = bearer;
        this.username = username;
    }


    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
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
