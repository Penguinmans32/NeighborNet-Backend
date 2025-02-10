package com.example.neighbornetbackend.model;

import java.util.Map;

public class MicrosoftOAuth2UserInfo extends OAuth2UserInfo {

    public MicrosoftOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

   @Override
   public String getName() {
        String displayName = (String) attributes.get("displayName");
        if (displayName != null) return displayName;

        String givenName = (String) attributes.get("givenName");
        String surname = (String) attributes.get("surname");
        if(givenName != null && surname != null) {
            return givenName + " " + surname;
        }
        return (String) attributes.get("userPrincipalName");
   }

    @Override
    public String getEmail() {
        String mail = (String) attributes.get("mail");
        if (mail != null) return mail;
        return (String) attributes.get("userPrincipalName");
    }

    @Override
    public String getImageUrl() {
        return null;
    }
}