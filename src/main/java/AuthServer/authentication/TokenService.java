package AuthServer.authentication;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class TokenService {

    private final JwtEncoder encoder;

    @Autowired
    private OAuth2TokenGenerator<?> tokenGenerator;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();

        List<String> rights = new ArrayList<>();
        rights.add("USER");
        rights.add("ADMIN");

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:9000")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .subject(authentication.getName())
                .claim("rights", rights)
                .build();

        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public Map<String, String> generateToken2(Authentication authentication) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId("my-client");
        log.info("Token Generator Class: {}", tokenGenerator.getClass().getName());
        log.info("registered client -> {}", registeredClient.getClientId());        // 3. Create a base OAuth2Authorization builder with user and client info
        OAuth2Authorization.Builder authorizationBuilder =
                OAuth2Authorization.withRegisteredClient(registeredClient)
                        .principalName(authentication.getName())
                        // Use a custom grant type if needed (or use one of the standard ones)
                        .authorizationGrantType(new AuthorizationGrantType("password"));

        AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
        if (authorizationServerContext == null) {
            throw new IllegalStateException("AuthorizationServerContext is not set in the holder");
        }

        // 4. Build token generation context for the access token

        List<GrantedAuthority> updatedAuthorities = new ArrayList<>();
        List<String> newAuthorities = List.of("USER", "ADMIN"); // List of authorities to add
        List<GrantedAuthority> authoritiesToAdd = newAuthorities.stream()
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());

        updatedAuthorities.addAll(authoritiesToAdd);

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
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .build();

        OAuth2Token accessToken = tokenGenerator.generate(accessTokenContext);


        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
                registeredClient,
                ClientAuthenticationMethod.NONE,
                null
        );

        // 5. Build token generation context for the refresh token
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(newAuthentication)
                .authorization(authorizationBuilder.build())
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();

        OAuth2Token refreshToken = tokenGenerator.generate(refreshTokenContext);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken.getTokenValue());
        tokens.put("refresh_token", refreshToken.getTokenValue());

        return tokens;
    }

}