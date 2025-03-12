package AuthServer.authentication;

import lombok.Getter;

@Getter
public class ThirdPartyUser {
    private final String username;
    private final String displayName;

    public ThirdPartyUser(String username, String displayName) {
        this.username = username;
        this.displayName = displayName;
    }

}