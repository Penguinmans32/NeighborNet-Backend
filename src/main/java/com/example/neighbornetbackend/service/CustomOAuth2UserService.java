package com.example.neighbornetbackend.service;

import com.example.neighbornetbackend.exception.OAuth2AuthenticationProcessingException;
import com.example.neighbornetbackend.model.OAuth2UserInfo;
import com.example.neighbornetbackend.model.OAuth2UserInfoFactory;
import com.example.neighbornetbackend.model.User;
import com.example.neighbornetbackend.repository.UserRepository;
import com.example.neighbornetbackend.security.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;



@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger log = LoggerFactory.getLogger(CustomOAuth2UserService.class);
    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        log.info("OAuth2User attributes: {}", oAuth2User.getAttributes());

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (Exception ex) {
            try {
                log.error("Error processing OAuth2 user", ex);
                throw new OAuth2AuthenticationProcessingException("Failed to process OAuth2 user");
            } catch (OAuth2AuthenticationProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) throws OAuth2AuthenticationProcessingException {
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        log.info("Processing OAuth2 user for provider: {}", registrationId);

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId,
                oAuth2User.getAttributes()
        );

        String email = oAuth2UserInfo.getEmail();
        log.info("OAuth2 user email: {}", email);
        String currentProvider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        Optional<User> userOptional = userRepository.findByEmail(email);

        User user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
            log.info("Existing user found with email: {}", email);
            if(!currentProvider.equals(user.getProviderId())) {
                user.setProviderId(currentProvider);
                user.setProvider(oAuth2UserInfo.getId());
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            log.info("Creating new user with email: {}", email);
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        User savedUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Failed to save user"));

        log.info("Saved user ID: {}, Provider: {}", savedUser.getId(), savedUser.getProvider());

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = new User();
        user.setProvider(oAuth2UserRequest.getClientRegistration().getRegistrationId());
        user.setProviderId(oAuth2UserInfo.getId());
        user.setUsername(oAuth2UserInfo.getName());
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setEmailVerified(true);
        user.setPassword(""); // Set empty password for OAuth2 users
        user.setImageUrl(oAuth2UserInfo.getImageUrl());
        user.setRole("ROLE_USER");
        User savedUser = userRepository.save(user);
        log.info("New user registered - ID: {}, Email: {}, Provider: {}",
                savedUser.getId(), savedUser.getEmail(), savedUser.getProvider());  // Debug log
        return savedUser;
    }

    private User updateExistingUser(User user, OAuth2UserInfo oAuth2UserInfo) {
        if (oAuth2UserInfo.getName() != null) {
            user.setUsername(oAuth2UserInfo.getName());
        }
        if (oAuth2UserInfo.getImageUrl() != null) {
            user.setImageUrl(oAuth2UserInfo.getImageUrl());
        }

        User savedUser = userRepository.save(user);
        log.info("User updated - ID: {}, Email: {}, Provider: {}",
                savedUser.getId(), savedUser.getEmail(), savedUser.getProvider());

        return savedUser;
    }
}
