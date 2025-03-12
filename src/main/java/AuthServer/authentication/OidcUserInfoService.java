package AuthServer.authentication;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class OidcUserInfoService {

    private final UserInfoRepository userInfoRepository = new UserInfoRepository();

    public OidcUserInfo loadUser(String username) {
        return new OidcUserInfo(this.userInfoRepository.findByUsername(username));
    }

    static class UserInfoRepository {

        private final Map<String, Map<String, Object>> userInfo = new HashMap<>();

        public UserInfoRepository() {
            this.userInfo.put("user", createUser());
        }

        public Map<String, Object> findByUsername(String username) {
            return this.userInfo.get(username);
        }

        private static Map<String, Object> createUser() {
            return Map.of(
                    "user", Map.of(
                            "id", 1,
                            "username", "user",
                            "name", "User",
                            "email", "user@email.com"
                    )
            );
        }
    }
}