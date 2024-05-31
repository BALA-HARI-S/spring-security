package security.spring.demoapp.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secured")
@Slf4j
public class SecuredController {

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> sayHello() {
        log.info("Entering sayHello()");
        String hello = "Hello from Secured Endpoint";
        log.info("Leaving sayHello()");
        return ResponseEntity.ok(hello);
    }
}
