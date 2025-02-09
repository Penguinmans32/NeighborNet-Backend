package com.example.neighbornetbackend.security;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        String token = tokenProvider.generateToken(authentication);

        // Update headers
        response.setHeader("Access-Control-Allow-Origin", frontendUrl);
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Cross-Origin-Opener-Policy", "unsafe-none");
        response.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");

        // Simplified success script
        String htmlResponse = String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Success</title>
            </head>
            <body>
                <script>
                    function closeWindow() {
                        if (window.opener) {
                            try {
                                window.opener.postMessage(
                                    { 
                                        type: 'oauth2_success', 
                                        token: '%s'
                                    }, 
                                    '%s'
                                );
                            } catch (err) {
                                console.error('Post message error:', err);
                            }
                        }
                        setTimeout(function() {
                            window.close();
                        }, 1000);
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