package com.example.neighbornetbackend.model;

import java.util.Map;

public class MicrosoftOAuth2UserInfo extends OAuth2UserInfo {

    public MicrosoftOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("displayName");
    }

    @Override
    public String getEmail() {
        return (String) attributes.getOrDefault("mail",
                attributes.getOrDefault("userPrincipalName", null));
    }

    @Override
    public String getImageUrl() {
        return null;
    }
}