package com.spotify.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;

import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

import com.spotify.security.CustomUserDetails;

import java.util.List;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
@Component
public class JwtUtil {
    // Secret key must be Base64-encoded and long enough for security
    @Value("${jwt.secret}")
    private String SECRET_KEY;

    @Value("${jwt.accessTokenExpiration}")
    private long ACCESS_TOKEN_EXPIRATION;

    // Generate the signing key from the secret key
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Generate a JWT token
    public String generateAccessToken(CustomUserDetails user) {

        return Jwts.builder()
                .setSubject(String.valueOf(user.getId())) // Store userId in the subject
                .claim("roles", user.getRoles()) // Store username in claims
                .setIssuedAt(new Date()) // Add issued time
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION)) // Set expiration
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Use secure algorithm
                .compact();

    }

    // Extract username from the token
    public String extractUsername(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("username", String.class); // Extract username from claims
    }

    // Extract userId from the token
    public Long extractUserId(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return Long.parseLong(claims.getSubject()); // Extract userId from subject
    }

    // Validate the token
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            // Log token expiration
            System.err.println("Token has expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            // Log unsupported token
            System.err.println("Unsupported token: " + e.getMessage());
        } catch (MalformedJwtException e) {
            // Log malformed token
            System.err.println("Malformed token: " + e.getMessage());
        } catch (@SuppressWarnings("deprecation") SignatureException e) {
            // Log invalid signature
            System.err.println("Invalid JWT signature: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            // Log empty or invalid token
            System.err.println("Empty or invalid token: " + e.getMessage());
        }
        return false;
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Lấy roles từ token
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> claims.get("roles", List.class));
    }

    // Kiểm tra token hết hạn chưa
    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public Date getExpirationFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey()) // Sửa lỗi ở đây
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }

}