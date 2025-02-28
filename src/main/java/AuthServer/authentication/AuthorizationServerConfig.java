package AuthServer.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        // Create a new OAuth2AuthorizationServerConfigurer instance
//        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
//                new OAuth2AuthorizationServerConfigurer();
//
//        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
//
//        http
//                .securityMatcher(endpointsMatcher)
//                // Disable CSRF for simplicity (enable it in production as needed)
//                .csrf(csrf -> csrf.disable())
//                // Permit access to the login endpoint without authentication
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/auth/login").permitAll()
//                        .anyRequest().authenticated()
//                )
//                // Disable form login so that Spring Security does not redirect to a login page
//                .formLogin(form -> form.disable())
//                // Optionally, you can enable HTTP Basic authentication if needed
//                .httpBasic(Customizer.withDefaults());
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Create a new OAuth2AuthorizationServerConfigurer instance
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        // Obtain the endpoints matcher that covers the authorization server endpoints (e.g. /oauth2/authorize, /oauth2/token, /oauth2/jwks, etc.)
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                // Only apply security rules to endpoints managed by the authorization server
                .securityMatcher(endpointsMatcher)
                // Configure authorization: all requests must be authenticated
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // Disable CSRF protection on these endpoints
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                // Apply the authorization server configuration, which registers all necessary endpoints including /oauth2/jwks
                .apply(authorizationServerConfigurer);

        // Optionally, you can configure form login if desired
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("my-client")
                .clientSecret("{noop}my-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
                .scope("read")
                .scope("write")
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}

