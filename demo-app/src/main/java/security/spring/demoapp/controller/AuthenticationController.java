package security.spring.demoapp.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.spring.demoapp.entity.AuthenticationRequest;
import security.spring.demoapp.entity.AuthenticationResponse;
import security.spring.demoapp.entity.RegisterRequest;
import security.spring.demoapp.service.AuthenticationService;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        log.info("Entering register()");
        var register = authenticationService.register(request);
        log.info("Leaving register()");
        return ResponseEntity.ok(register);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        log.info("Entering authenticate()");
        var authenticate = authenticationService.authenticate(request);
        log.info("Leaving authenticate()");
        return ResponseEntity.ok(authenticate);
    }
}
