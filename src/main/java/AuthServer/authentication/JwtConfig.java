package AuthServer.authentication;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Configuration
public class JwtConfig {

    private final RsaKeyProperties rsaKeys;

    public JwtConfig(RsaKeyProperties rsaKeys) {
        this.rsaKeys = rsaKeys;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        RSAKey rsaKey = new RSAKey.Builder(rsaKeys.publicKey())
                .privateKey(rsaKeys.privateKey())
                .keyID("my-rsa-key")
                .algorithm(JWSAlgorithm.RS256)
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            log.info("Inside jwtCustomizer for token type: {}", context.getTokenType());

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication authentication = context.getPrincipal();
                if (authentication != null) {
                    // Extract rights from the principal's authorities
                    List<String> rights = authentication.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority) // Get authority as string
                            .collect(Collectors.toList());

                    log.info("Processed rights for user {}: {}", authentication.getName(), rights);

                    context.getClaims().claim("rights", rights);  // Set the "rights" claim
                } else {
                    log.warn("No authentication principal found");
                    context.getClaims().claim("rights", List.of("USER")); // Fallback
                }
            }
        };
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder,
                                                  OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer); // Set the customizer here

        log.info("Custom JWT tokenGenerator");

        // jwtGenerator uses its own customizer type, so it can remain as is or be separately defined
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        // accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);

        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }
}

