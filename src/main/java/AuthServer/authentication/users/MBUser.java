package AuthServer.authentication.users;

import java.util.List;

public record MBUser(String username, String password, List<String> rights, String name) {
}
