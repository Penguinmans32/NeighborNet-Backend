package com.example.neighbornetbackend.model;


import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "email_verification_tokens")
public class EmailVerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private Instant expiryDate;

    private boolean verified = false;

    private static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000;

    public EmailVerificationToken() {
        this.expiryDate = Instant.now().plusMillis(EXPIRATION_TIME);
    }

    public EmailVerificationToken(User user, String token) {
        this.user = user;
        this.token = token;
        this.expiryDate = Instant.now().plusMillis(EXPIRATION_TIME);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Instant expiryDate) {
        this.expiryDate = expiryDate;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }
}