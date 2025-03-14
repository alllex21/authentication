package AuthServer.authentication;

import AuthServer.authentication.requests.AuthRequest;
import AuthServer.authentication.requests.RefreshRequest;
import AuthServer.authentication.users.LoginService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final TokenService tokenService;
    private final LoginService loginService;

    public AuthController(TokenService tokenService, LoginService loginService) {
        this.tokenService = tokenService;
        this.loginService = loginService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody AuthRequest request) {
            Map<String, String> token = loginService.loginUser(request);
            return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody RefreshRequest request) {
        Map<String, String> token = tokenService.refreshAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(token);
    }
}
