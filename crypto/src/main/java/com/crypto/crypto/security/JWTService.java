package com.crypto.crypto.security;

import java.security.Key;
import java.security.Signature;
import java.util.Date;
import java.security.Key;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

@Service
public class JWTService {
    private final Key key;
    private final long expirationMs;

    public JWTService(
        @Value("${app.jwt.secret}") String secret,
        @Value("${app.jwt.expiration}") long expirationMs
    ){
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.expirationMs = expirationMs;
    }

    public String generateToken(String username){
         Date now = new Date();
         Date exp = new Date(now.getTime()+expirationMs);
         return Jwts.builder()
         .setSubject(username)
         .setIssuedAt(now)
         .setExpiration(exp)
         .signWith(key, SignatureAlgorithm.HS256)
         .compact();
    }

    public String extractUsername(String token){
        return parseClaims(token).getBody().getSubject();
    }


    public boolean isValid(String token){
        try{
            parseClaims(token);
            return true;
        }catch(JwtException | IllegalArgumentException e){
            return false;
        }
    }

    private Jws<Claims> parseClaims(String token){
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }


}
