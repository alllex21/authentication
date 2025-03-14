package AuthServer.authentication.users;

import AuthServer.authentication.TokenService;
import AuthServer.authentication.requests.AuthRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class LoginService {

    private final TokenService tokenService;
    private final UserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
    private final AuthenticationManager authenticationManager;

    public LoginService(TokenService tokenService, UserService userService, AuthenticationManager authenticationManager) {
        this.tokenService = tokenService;
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    public Map<String, String> loginUser(AuthRequest request){

        UserDetails userDetails = userService.loadUserByUsername(request.getUsername());
        String password = request.getPassword();

        if(userDetails != null){

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), bCryptPasswordEncoder.encode(request.getPassword())));

            if(authentication.isAuthenticated()){
                return tokenService.generateToken(authentication, userDetails);
            }
            throw new UsernameNotFoundException("Invalid username or password");

        }else {
            throw new UsernameNotFoundException("User not found");
        }
    }
}
