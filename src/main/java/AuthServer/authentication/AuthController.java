package AuthServer.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private final ThirdPartyAuthenticationProvider authenticationManager;

    public AuthController(ThirdPartyAuthenticationProvider authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletResponse httpResponse, HttpServletRequest httpRequest, @RequestBody AuthRequest request) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());

        try {
            // Delegate authentication to the AuthenticationManager which uses our custom provider
            Authentication auth = authenticationManager.authenticate(authToken);
            // On success, store the authentication in the SecurityContext
            SecurityContextHolder.getContext().setAuthentication(auth);

            String origin = httpRequest.getHeader(HttpHeaders.ORIGIN);
            httpResponse.setHeader("Access-Control-Allow-Credentials", "true");

            httpResponse.setHeader("Access-Control-Allow-Origin", origin);
            return new ResponseEntity<>("login successful", HttpStatus.OK);
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
}
