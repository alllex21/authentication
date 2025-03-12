package AuthServer.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class AuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}

	/** Define in-memory user for authentication */
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withUsername("user")
				.password("{noop}password") // No-op encoding for simplicity; use a proper encoder in production
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
}
