package com.example.neighbornetbackend.controller;


import com.example.neighbornetbackend.dto.*;
import com.example.neighbornetbackend.exception.TokenRefreshException;
import com.example.neighbornetbackend.model.RefreshToken;
import com.example.neighbornetbackend.model.User;
import com.example.neighbornetbackend.repository.UserRepository;
import com.example.neighbornetbackend.security.CustomUserDetails;
import com.example.neighbornetbackend.security.JwtTokenProvider;
import com.example.neighbornetbackend.service.EmailService;
import com.example.neighbornetbackend.service.EmailVerificationService;
import com.example.neighbornetbackend.service.RefreshTokenService;
import jakarta.mail.MessagingException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final EmailVerificationService emailVerificationService;
    private final EmailService emailService;

    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenProvider tokenProvider, RefreshTokenService refreshTokenService, EmailVerificationService emailVerificationService, EmailService emailService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.refreshTokenService = refreshTokenService;
        this.emailVerificationService = emailVerificationService;
        this.emailService = emailService;
    }

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        try {
            emailVerificationService.verifyEmail(token);
            return ResponseEntity.ok("Email verified successfully!");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {
        if(userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }
        if(userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }

        User user = new User();
        user.setUsername(signupRequest.getUsername());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        user.setEmailVerified(false);

        userRepository.save(user);

        // Create verification token and send email
        String token = emailVerificationService.createVerificationToken(user);
        try {
            emailService.sendVerificationEmail(user.getEmail(), token);
            return ResponseEntity.ok("User registered successfully! Please check your email to verify your account.");
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("User registered but failed to send verification email.");
        }
    }

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        User user = userRepository.findByUsernameOrEmail(loginRequest.getUsername(), loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if(!user.isEmailVerified()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Please verify your email before loggin in.");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        refreshTokenService.invalidateAllUserTokens(userDetails.getUser().getId());

        long activeTokens = refreshTokenService.countActiveTokensForUser(userDetails.getUser().getId());
        if (activeTokens > 5) {
            refreshTokenService.invalidateAllUserTokens(userDetails.getUser().getId());
        }

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getUser().getId());

        return ResponseEntity.ok(new AuthResponse(jwt,
                refreshToken.getToken(),
                "Bearer",
                userDetails.getUsername()));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(token -> {
                    if (refreshTokenService.isRefreshTokenExpired(token)) {
                        refreshTokenService.deleteByUserId(token.getUser().getId());
                        throw new TokenRefreshException(token.getToken(),
                                "Refresh token was expired. Please make a new signin request");
                    }

                    String newAccessToken = tokenProvider.generateTokenFromUsername(token.getUser().getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestBody LogOutRequest logOutRequest) {
        refreshTokenService.deleteByUserId(logOutRequest.getUserId());
        return ResponseEntity.ok("Log out successful!");
    }

    @PostMapping("/logout-all-devices")
    public ResponseEntity<?> logoutFromAllDevices(@RequestBody LogOutRequest logOutRequest) {
        refreshTokenService.invalidateAllUserTokens(logOutRequest.getUserId());
        return ResponseEntity.ok("Logged out from all devices successfully!");
    }

    @GetMapping("/check-token")
    public ResponseEntity<?> checkTokenValidity(@RequestParam String refreshToken) {
        return refreshTokenService.findByToken(refreshToken)
                .map(token -> {
                    boolean isExpired = refreshTokenService.isRefreshTokenExpired(token);
                    Map<String, Object> response = new HashMap<>();
                    response.put("token", refreshToken);
                    response.put("isExpired", isExpired);
                    response.put("username", token.getUser().getUsername());
                    response.put("expiryDate", token.getExpiryDate());

                    return ResponseEntity.ok(response);
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Collections.singletonMap("message", "Token not found")));
    }
}
