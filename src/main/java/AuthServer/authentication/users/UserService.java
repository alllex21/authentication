package AuthServer.authentication.users;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService implements UserDetailsService {

    private final List<MBUser> users = List.of(
            new MBUser("user", "password", List.of("USER"), "User One"),
            new MBUser("admin", "password", List.of("USER", "ADMIN"), "User Two")
    );

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MBUser foundUser = users.stream()
                .filter(user -> user.username().equals(username))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return new CustomUserDetails(foundUser);
    }
}
