package com.busanit501.boot501.security.filter;

import com.busanit501.boot501.security.exception.RefreshTokenException;
import com.busanit501.boot501.util.JWTUtil;
import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final String refreshPath;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        log.info("RefreshTokenFilter path: " + path);

        if (!path.equals(refreshPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.info("RefreshTokenFilter running...");

        Map<String, String> tokens = parseRequestJSON(request);

        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken: " + accessToken);
        log.info("refreshToken: " + refreshToken);

        try {
            checkAccessToken(accessToken);
        } catch (RefreshTokenException ex) {
            ex.sendResponseError(response);
            return;
        }

        Map<String, Object> refreshClaims;

        try {
            refreshClaims = checkRefreshToken(refreshToken);
        } catch (RefreshTokenException ex) {
            ex.sendResponseError(response);
            return;
        }

        Integer exp = (Integer) refreshClaims.get("exp");

        Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);
        Date current = new Date(System.currentTimeMillis());

        long gapTime = expTime.getTime() - current.getTime();

        log.info("current: " + current);
        log.info("expTime: " + expTime);
        log.info("gap: " + gapTime);

        String username = (String) refreshClaims.get("username");

        String accessTokenValue = jwtUtil.generateToken(Map.of("username", username), 1);
        String refreshTokenValue = tokens.get("refreshToken");

        if (gapTime < (1000L * 60 * 60 * 24 * 3)) {
            log.info("new Refresh Token required...");
            refreshTokenValue = jwtUtil.generateToken(Map.of("username", username), 3);
        }

        log.info("Refresh Token result - accessToken: " + accessTokenValue
                + ", refreshToken: " + refreshTokenValue);

        sendTokens(accessTokenValue, refreshTokenValue, response);
    }

    private Map<String, String> parseRequestJSON(HttpServletRequest request) {

        try (Reader reader = new InputStreamReader(request.getInputStream())) {
            Gson gson = new Gson();
            return gson.fromJson(reader, Map.class);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    private void checkAccessToken(String accessToken) throws RefreshTokenException {

        try {
            jwtUtil.validateToken(accessToken);
        } catch (ExpiredJwtException ex) {
            log.info("Access Token has expired");
        } catch (Exception ex) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }

    private Map<String, Object> checkRefreshToken(String refreshToken)
            throws RefreshTokenException {

        try {
            return jwtUtil.validateToken(refreshToken);
        } catch (ExpiredJwtException ex) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        } catch (MalformedJwtException ex) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
    }

    private void sendTokens(String accessTokenValue,
                            String refreshTokenValue,
                            HttpServletResponse response) {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();

        String jsonStr = gson.toJson(
                Map.of("accessToken", accessTokenValue,
                        "refreshToken", refreshTokenValue));

        try {
            response.getWriter().println(jsonStr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
