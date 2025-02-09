package com.example.neighbornetbackend.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class OAuth2AuthenticationDebugger {
    private static final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationDebugger.class);

    public void logOAuth2Request(OAuth2UserRequest userRequest) {
        log.info("OAuth2 Provider: {}", userRequest.getClientRegistration().getRegistrationId());
        log.info("Access Token: {}", userRequest.getAccessToken().getTokenValue());
        log.info("Client ID: {}", userRequest.getClientRegistration().getClientId());
        log.info("Scopes: {}", userRequest.getAccessToken().getScopes());
    }

    public void logOAuth2User(OAuth2User oauth2User) {
        log.info("OAuth2 User Attributes: {}", oauth2User.getAttributes());
        log.info("OAuth2 User Authorities: {}", oauth2User.getAuthorities());
    }

    public void logOAuth2Error(OAuth2AuthenticationException ex) {
        log.error("OAuth2 Authentication Error: {}", ex.getMessage());
        if (ex.getCause() != null) {
            log.error("Caused by: {}", ex.getCause().getMessage());
        }
    }
}