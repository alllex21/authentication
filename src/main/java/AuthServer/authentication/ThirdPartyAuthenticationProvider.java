package AuthServer.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ThirdPartyAuthenticationProvider implements AuthenticationProvider {

    private final ThirdPartyAuthService thirdPartyAuthService;

    public ThirdPartyAuthenticationProvider(ThirdPartyAuthService thirdPartyAuthService) {
        this.thirdPartyAuthService = thirdPartyAuthService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        // Delegate to external authentication service
        ThirdPartyUser thirdPartyUser = thirdPartyAuthService.authenticate(username, password);
        if (thirdPartyUser == null) {
            throw new BadCredentialsException("Invalid credentials");
        }

        // Create an authenticated token with authorities; adjust roles as needed.
        return new UsernamePasswordAuthenticationToken(
                thirdPartyUser,
                password,
                List.of(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN"),
                        new SimpleGrantedAuthority("USER"),
                        new SimpleGrantedAuthority("ADMIN"))
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}