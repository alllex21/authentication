package AuthServer.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CustomAuthorizationServerContextFilter extends OncePerRequestFilter {

    private final AuthorizationServerSettings settings;

    public CustomAuthorizationServerContextFilter(AuthorizationServerSettings settings) {
        this.settings = settings;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if ("/login".equals(request.getRequestURI())) {
            AuthorizationServerContext context = new AuthorizationServerContext() {
                @Override
                public String getIssuer() {
                    return settings.getIssuer();
                }

                @Override
                public AuthorizationServerSettings getAuthorizationServerSettings() {
                    return settings;
                }
            };
            AuthorizationServerContextHolder.setContext(context);
        }
        try {
            filterChain.doFilter(request, response);
        } finally {
            AuthorizationServerContextHolder.resetContext(); // Clean up after the request
        }
    }
}