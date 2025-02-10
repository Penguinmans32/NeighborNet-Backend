package com.example.neighbornetbackend.security;


import com.example.neighbornetbackend.model.User;
import com.example.neighbornetbackend.repository.UserRepository;
import com.example.neighbornetbackend.service.CustomOAuth2UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    @Value("${app.frontend.url}")
    private String frontendUrl;

    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    public OAuth2AuthenticationSuccessHandler(
            JwtTokenProvider tokenProvider,
            UserRepository userRepository,
            HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        this.tokenProvider = tokenProvider;
        this.userRepository = userRepository;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 authentication success for principal: {}", authentication.getName());

        if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = oauth2User.getAttributes();
            log.info("OAuth2 user attributes: {}", attributes);

            // Get email
            String email = (String) attributes.get("mail");  // Microsoft specific
            if (email == null) {
                email = (String) attributes.get("email");
            }
            if (email == null) {
                email = (String) attributes.get("userPrincipalName");
            }

            // Get name
            String name = (String) attributes.get("displayName");
            if (name == null) {
                name = (String) attributes.get("givenName");
                String surname = (String) attributes.get("surname");
                if (surname != null) {
                    name = name != null ? name + " " + surname : surname;
                }
            }
            if (name == null) {
                // Fallback to email prefix if no name is available
                name = email.substring(0, email.indexOf('@'));
            }

            log.info("Processing OAuth2 user - Email: {}, Name: {}", email, name);

            // Find or create user
            String finalEmail = email;
            String finalName = name;
            User user = userRepository.findByEmail(email).orElseGet(() -> {
                User newUser = new User();
                newUser.setEmail(finalEmail);
                newUser.setUsername(finalName);  // Set the username here
                newUser.setProvider("microsoft");
                newUser.setProviderId((String) attributes.get("sub"));
                newUser.setEmailVerified(true);
                newUser.setPassword("");
                log.info("Creating new user with username: {}", finalName);
                return userRepository.save(newUser);
            });

            log.info("User saved/updated in database with ID: {}", user.getId());
        }

        String token = tokenProvider.generateToken(authentication);

        response.setHeader("Access-Control-Allow-Origin", frontendUrl);
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Cross-Origin-Opener-Policy", "unsafe-none");
        response.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");

        String htmlResponse = String.format("""
            <!DOCTYPE html>
            <html>
            <head><title>Authentication Success</title></head>
            <body>
                <script>
                    function closeWindow() {
                        if (window.opener) {
                            try {
                                window.opener.postMessage(
                                    { type: 'oauth2_success', token: '%s' }, 
                                    '%s'
                                );
                            } catch (err) {
                                console.error('Post message error:', err);
                            }
                        }
                        setTimeout(function() { window.close(); }, 1000);
                    }
                    setTimeout(closeWindow, 500);
                </script>
            </body>
            </html>
            """, token, frontendUrl);

        clearAuthenticationAttributes(request, response);
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write(htmlResponse);
        response.getWriter().flush();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }
}