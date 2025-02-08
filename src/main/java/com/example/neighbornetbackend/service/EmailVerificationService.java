package com.example.neighbornetbackend.service;

import com.example.neighbornetbackend.model.EmailVerificationToken;
import com.example.neighbornetbackend.model.User;
import com.example.neighbornetbackend.repository.EmailVerificationTokenRepository;
import com.example.neighbornetbackend.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@Transactional
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    public EmailVerificationService(EmailVerificationTokenRepository tokenRepository, EmailService emailService, UserRepository userRepository) {
        this.tokenRepository = tokenRepository;
        this.emailService = emailService;
        this.userRepository = userRepository;
    }

    @Transactional
    public String createVerificationToken(User user) {
        String token = UUID.randomUUID().toString();
        EmailVerificationToken verificationToken = new EmailVerificationToken(user, token);
        tokenRepository.save(verificationToken);
        return token;
    }

    @Transactional(readOnly = true)
    public EmailVerificationToken getVerificationToken(String token) {
        return tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));
    }

    @Transactional
    public void verifyEmail(String token) {
        System.out.println("Verifying email with token: " + token);

        EmailVerificationToken verificationToken = getVerificationToken(token);

        if (verificationToken.isExpired()) {
            throw new RuntimeException("Token has expired");
        }

        User user = verificationToken.getUser();
        System.out.println("Found user: " + user.getEmail());
        System.out.println("Current verification status: " + user.isEmailVerified());

        // Update and save user first
        user.setEmailVerified(true);
        User savedUser = userRepository.saveAndFlush(user);

        // Then update and save token
        verificationToken.setVerified(true);
        tokenRepository.save(verificationToken);

        System.out.println("After save - User ID: " + savedUser.getId());
        System.out.println("After save - Email verified: " + savedUser.isEmailVerified());
    }
}