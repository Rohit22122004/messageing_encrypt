package com.example.milatary.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

public class JwtUtil {

    private static final String SECRET = "super-secret-key-super-secret-key";
    private static final Key key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    private static final long EXPIRATION_MS = 24 * 60 * 60 * 1000; // 1 day

    public static String generateToken(String userId) {
        System.out.println("[JWT DEBUG] Generating with key hash: " + key.hashCode());
        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public static String parseUserId(String token) {
        try {
            System.out.println("[JWT DEBUG] Parsing with key hash: " + key.hashCode());
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        } catch (Exception e) {
            System.out.println("[JWT DEBUG] JWT validation failed: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static String getUserIdFromAuthHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;
        String token = authHeader.substring(7);
        return parseUserId(token);
    }
}
