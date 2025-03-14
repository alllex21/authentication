package AuthServer.authentication.requests;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}
