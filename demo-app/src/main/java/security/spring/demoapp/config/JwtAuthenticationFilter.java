package security.spring.demoapp.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import security.spring.demoapp.service.JwtService;

import java.io.IOException;
import java.util.Objects;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    // Want our own implementation of this interface so create @Bean of TYPE: UserDetailsService
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        log.info("Entering JwtAuthenticationFilter doFilterInternal(): " +
                "Request: %n{} %nResponse : %n{} %nFilter Chain : %n{}",request.toString(), response.toString(), filterChain.toString());

        // Check whether the REQUEST has JWT TOKEN
        // Retrieved Authentication Header
        final String authHeader = request.getHeader("Authorization");
        log.info("doFilterInternal() auth Header: {}", authHeader);

        // Retrieved Bearer/Access Token form the Authentication Header
        final String jwt;
        final String userEmail;

        if (Objects.isNull(authHeader) || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
        } else {
            // Retrieve Bearer/Access Token
            jwt = authHeader.substring(7);
            log.info("doFilterInternal() JWT from auth Header: {}", jwt);

            // After checking the jwt token, We need to call the UserDetailService to check whether the USER
            // already within the database or not. But to do that need to call a JWT Service to extract the USERNAME
            userEmail = jwtService.extractUsername(jwt);

            // Check whether the USER was Authenticated or Not
            // If we have USER but Not Authenticate the user
            if (!Objects.isNull(userEmail) && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                // check if TOKEN is still valid
                if (jwtService.isTokenValid(jwt, userDetails)){
                    // If Valid - UPDATE SecurityContext
                    // Need this TYPE:OBJECT to UPDATE the Security Context
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails.getUsername(),
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    System.out.println("authToken = " + authToken);
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request, response);
        }
        log.info("Leaving JwtAuthenticationFilter doFilterInternal()");
    }
}
