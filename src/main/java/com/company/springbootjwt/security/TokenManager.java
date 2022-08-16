package com.company.springbootjwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenManager {

    private static final String secretKey = "Parvin";
    private static final long expirationTime = 5*60*100;

    public String generateToken(String username){
        return Jwts.builder()
                .setSubject(username)
                .setIssuer("Parvin")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+expirationTime))
                .signWith(SignatureAlgorithm.ES256,secretKey)
                .compact();
    }

    public boolean tokenValidate(String token){
        if (getUsernameToken(token) !=null && isExpired(token)){
            return true;
        }
        return false;
    }

    public String getUsernameToken(String token){
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    public boolean isExpired(String token){
        Claims claims = getClaims(token);
        return claims.getExpiration().before(new Date());
    }

    private Claims getClaims(String token)
    {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
