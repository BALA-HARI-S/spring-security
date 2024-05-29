package security.spring.demoapp.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
// import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    private static final String SECRET_KEY = "089d6c4b9c023c87ed66229a7a6b4751222f317b4d5d66b2";

    public String extractUsername(String token) {
        log.info("Entering JwtService - extractUsername()");
        // String username = extractClaim(token, Claims::getSubject);
        String username = extractSubjectClaim(token);
        log.info("Leaving JwtService - extractUsername()");
        return username;
    }

//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        log.info("Entering JwtService - extractClaim()");
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }

    public String extractSubjectClaim(String token) {
        log.info("Entering JwtService - extractSubjectClaim()");
        final Claims claims = extractAllClaims(token);
        String username = claims.getSubject();
        log.info("Leaving JwtService - extractSubjectClaim()");
        return username;
    }

    public Date extractExpirationDateClaim(String token) {
        log.info("Entering JwtService - extractExpirationDateClaim()");
        final Claims claims = extractAllClaims(token);
        Date expirationDate = claims.getExpiration();
        log.info("Leaving JwtService - extractExpirationDateClaim()");
        return expirationDate;
    }

    public String generateToken(UserDetails userDetails) {
        log.info("Entering JwtService - generateToken( userDetails )");
        String token = generateToken(new HashMap<>(), userDetails);
        log.info("Leaving JwtService - generateToken( userDetails )");
        return token;
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        log.info("Entering JwtService - generateToken()");
        String token = Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
        log.info("Leaving JwtService - generateToken()");
        return token;
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        log.info("Entering JwtService - isTokenValid()");
        final String username = extractUsername(token);
        boolean isTokenExpired = (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        log.info("Leaving JwtService - isTokenValid()");
        return isTokenExpired;
    }

    private boolean isTokenExpired(String token) {
        log.info("Entering JwtService - isTokenExpired()");
        boolean isBefore = extractExpiration(token).before(new Date());
        log.info("Entering JwtService - isTokenExpired()");
        return isBefore;
    }

    private Date extractExpiration(String token) {
        log.info("Entering JwtService - extractExpiration()");
        Date date = extractExpirationDateClaim(token);
        log.info("Entering JwtService - extractExpiration()");
        return date;
    }

//    private Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }

    private Claims extractAllClaims(String token){
        log.info("Entering JwtService - extractAllClaims()");
        Claims payloads = Jwts
                .parserBuilder()
                // When Generate (or) Decode a token we need to use Signing-Key
                // Using signing key because of decoding-process
                // Using signing key for decoding the token
                .setSigningKey(getSigningKey())
                .build()
                // Parse the token and extract claims (payload)
                // Break down this token to get claims(payload) from this jwt
                .parseClaimsJws(token)
                .getBody();
        log.info("Leaving JwtService - extractAllClaims()");
        return payloads;
    }

    private Key getSigningKey() {
        log.info("Entering JwtService - getSigningKey()");
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
