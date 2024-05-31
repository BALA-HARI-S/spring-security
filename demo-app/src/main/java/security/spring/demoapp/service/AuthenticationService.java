package security.spring.demoapp.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import security.spring.demoapp.dao.UserRepository;
import security.spring.demoapp.entity.AuthenticationRequest;
import security.spring.demoapp.entity.AuthenticationResponse;
import security.spring.demoapp.entity.RegisterRequest;
import security.spring.demoapp.entity.Role;
import security.spring.demoapp.entity.User;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    // Create User, Save it to the Database and Return Generated Token
    public AuthenticationResponse register(RegisterRequest request) {
        log.info("Entering register()");
        var user = User.builder()
                        .firstname(request.getFirstname())
                        .lastname(request.getLastname())
                        .email(request.getEmail())
                        .password(passwordEncoder.encode(request.getPassword())) // Encode the Password before saving it to the Database
                        .role(Role.ROLE_USER)
                        .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var authResponse = AuthenticationResponse.builder().token(jwtToken).build();
        log.info("Leaving register()");
        return authResponse;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        log.info("Entering authenticate()");
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                        .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var authResponse = AuthenticationResponse.builder().token(jwtToken).build();
        log.info("Leaving authenticate()");
        return authResponse;
    }
}
