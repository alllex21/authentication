package AuthServer.authentication;

import org.springframework.stereotype.Service;

@Service
public class ThirdPartyAuthService {

    /**
     * Simulate third‑party user authentication.
     * Replace this with actual calls (e.g. using WebClient or RestTemplate) to your external service.
     */
    public ThirdPartyUser authenticate(String username, String password) {
        // Replace with real external authentication logic
        if ("user".equals(username) && "password".equals(password)) {
            return new ThirdPartyUser(username, "User Display Name");
        }
        return null;
    }
}