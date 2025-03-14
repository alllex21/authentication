package AuthServer.authentication.users;

import AuthServer.authentication.TokenService;
import AuthServer.authentication.requests.AuthRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class LoginService {

    private final TokenService tokenService;
    private final UserService userService;

    public LoginService(TokenService tokenService, UserService userService) {
        this.tokenService = tokenService;
        this.userService = userService;
    }

    public Map<String, String> loginUser(AuthRequest request){

        UserDetails userDetails = userService.loadUserByUsername(request.getUsername());

        if(userDetails != null){

            if(userDetails.getPassword().equals( request.getPassword()) && userDetails.getUsername().equals(request.getUsername())){
                return tokenService.generateToken(userDetails);
            }
            throw new UsernameNotFoundException("Bad password: " + request.getUsername());
        }else {
            throw new UsernameNotFoundException("User not found");
        }
    }
}
