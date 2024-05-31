package security.spring.demoapp.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import security.spring.demoapp.dao.UserRepository;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        log.info("Processing Bean userDetailsService()");
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    // Data Access Object which is responsible to fetch the UserDetails, Encode Password etc.
    @Bean
    public AuthenticationProvider authenticationProvider() {
        log.info("Entering Bean authenticationProvider()");
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        log.info("Leaving Bean authenticationProvider()");
        return authProvider;
    }

    // Authentication Manager - Authenticate User with Username and Password
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        log.info("Entering Bean authenticationManager()");
        AuthenticationManager authenticationManager = config.getAuthenticationManager();
        log.info("Leaving Bean authenticationManager()");
        return authenticationManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info("Processing Bean passwordEncoder()");
        return new BCryptPasswordEncoder();
    }
}
