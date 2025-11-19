package com.busanit501.boot501.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {

    // application.properties 에서 주입받는 시크릿 키
    @Value("${com.busanit501.jwt.secret}")
    private String key;

    public String generateToken(Map<String, Object> valueMap, int days) {

        log.info("generateToken with key..." + key);

        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("alg", "HS256");

        Map<String, Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);

        int time = (60 * 24) * days; // day → minutes

        return Jwts.builder()
                .setHeader(headers)
                .setClaims(payloads)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
                .signWith(SignatureAlgorithm.HS256, key.getBytes())
                .compact();
    }

    public Map<String, Object> validateToken(String token) throws JwtException {

        return Jwts.parser()
                .setSigningKey(key.getBytes())
                .parseClaimsJws(token)
                .getBody();
    }
}
