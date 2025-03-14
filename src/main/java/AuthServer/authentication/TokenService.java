package AuthServer.authentication;

import AuthServer.authentication.users.MBUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class TokenService {

    private final JwtEncoder encoder;

    private final OAuth2TokenGenerator<?> tokenGenerator;


    private final RegisteredClientRepository registeredClientRepository;

    private final OAuth2AuthorizationService authorizationService;

    private final AuthorizationServerSettings authorizationServerSettings;

    private final AuthenticationManager authenticationManager;

    public TokenService(JwtEncoder encoder, OAuth2TokenGenerator<?> tokenGenerator, RegisteredClientRepository registeredClientRepository,
                        OAuth2AuthorizationService authorizationService, AuthorizationServerSettings authorizationServerSettings,
                        AuthenticationManager authenticationManager) {
        this.encoder = encoder;
        this.tokenGenerator = tokenGenerator;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.authorizationServerSettings = authorizationServerSettings;
        this.authenticationManager = authenticationManager;
    }

    public Map<String, String> generateToken(UserDetails user) {
        AuthorizationServerContextHolder.setContext(getContext());

        try {
            RegisteredClient registeredClient = registeredClientRepository.findByClientId("my-client");

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

            OAuth2Authorization.Builder authorizationBuilder =
                    OAuth2Authorization.withRegisteredClient(registeredClient)
                            .principalName(authentication.getName())
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);

            AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
            if (authorizationServerContext == null) {
                throw new IllegalStateException("AuthorizationServerContext is not set in the holder");
            }

            List<GrantedAuthority> updatedAuthorities = new ArrayList<>();

            Collection<? extends GrantedAuthority> newAuthorities = user.getAuthorities();

            updatedAuthorities.addAll(newAuthorities);

            Authentication newAuthentication = new UsernamePasswordAuthenticationToken(
                    authentication.getPrincipal(),
                    authentication.getCredentials(),
                    updatedAuthorities
            );

            OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(newAuthentication)
                    .authorization(authorizationBuilder.build())
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .authorizationServerContext(authorizationServerContext)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .build();

            OAuth2AccessToken accessToken = generateAccessToken(accessTokenContext);

            OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(newAuthentication)
                    .authorization(authorizationBuilder.build())
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();

            OAuth2Token refreshToken = tokenGenerator.generate(refreshTokenContext);

            OAuth2Authorization authorization = authorizationBuilder
                    .id(authentication.getName())
                    .accessToken(accessToken)
                    .refreshToken((OAuth2RefreshToken) refreshToken)
                    .attribute(Principal.class.getName(), newAuthentication)
                    .build();

            authorizationService.save(authorization);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken.getTokenValue());
            tokens.put("refresh_token", refreshToken.getTokenValue());

            AuthorizationServerContextHolder.resetContext();

            return tokens;
        }finally {
            AuthorizationServerContextHolder.resetContext();
        }
    }

    public Map<String, String> refreshAccessToken(String refreshToken) {
        OAuth2Authorization authorization = authorizationService.findByToken(refreshToken, OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> existingRefreshToken = authorization.getRefreshToken();
        if (existingRefreshToken == null || existingRefreshToken.getToken().getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh token expired or invalid");
        }

        RegisteredClient registeredClient = registeredClientRepository.findById(authorization.getRegisteredClientId());
        if (registeredClient == null) {
            throw new IllegalStateException("Registered client not found");
        }

        Authentication principal = authorization.getAttribute(Principal.class.getName());
        if (principal == null) {
            throw new IllegalStateException("Principal not found in authorization");
        }

        AuthorizationServerContextHolder.setContext(getContext());

        try {
            AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
            if (authorizationServerContext == null) {
                throw new IllegalStateException("AuthorizationServerContext is not set");
            }
            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(principal)
                    .authorization(authorization)
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .authorizationServerContext(authorizationServerContext)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

            OAuth2AccessToken accessToken = generateAccessToken(tokenContext);

            OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
                    .accessToken(accessToken)
                    .build();

            authorizationService.save(updatedAuthorization);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken.getTokenValue());
            tokens.put("refresh_token", refreshToken);

            return tokens;
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }
    }


    private AuthorizationServerContext getContext() {

        AuthorizationServerContext context = new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return authorizationServerSettings.getIssuer();
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return authorizationServerSettings;
            }
        };

        return context;
    }

    private OAuth2AccessToken generateAccessToken(OAuth2TokenContext tokenContext) {
        OAuth2Token newAccessToken = tokenGenerator.generate(tokenContext);

        OAuth2AccessToken accessToken;

        if (newAccessToken instanceof Jwt) {
            Jwt jwt = (Jwt) newAccessToken;
            accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(),
                    jwt.getIssuedAt(),
                    jwt.getExpiresAt(),
                    (Set<String>) jwt.getClaimAsStringList("scope")
            );
        } else if (newAccessToken instanceof OAuth2AccessToken) {
            accessToken = (OAuth2AccessToken) newAccessToken;
        } else {
            throw new RuntimeException("Unsupported token type: " + newAccessToken.getClass().getName());
        }

        if (newAccessToken == null) {
            throw new RuntimeException("Failed to generate new access token");
        }

        return accessToken;
    }
}