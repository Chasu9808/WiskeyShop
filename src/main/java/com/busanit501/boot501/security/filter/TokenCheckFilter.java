package com.busanit501.boot501.security.filter;

import com.busanit501.boot501.security.CustomUserDetailsService;
import com.busanit501.boot501.security.exception.AccessTokenException;
import com.busanit501.boot501.util.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class TokenCheckFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService customUserDetailsService;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // /api/** 만 JWT 검사
        if (!path.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        log.info("TokenCheckFilter for path: " + path);

        try {
            Map<String, Object> payload = validateAccessToken(request);
            String username = (String) payload.get("username");

            log.info("username from token: " + username);

            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);
        } catch (AccessTokenException ex) {
            ex.sendResponseError(response);
        }
    }

    private Map<String, Object> validateAccessToken(HttpServletRequest request)
            throws AccessTokenException {

        String headerStr = request.getHeader("Authorization");

        if (headerStr == null || headerStr.length() < 8) {
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.UNACCEPT);
        }

        String tokenType = headerStr.substring(0, 6);
        String tokenStr = headerStr.substring(7);

        if (!tokenType.equalsIgnoreCase("Bearer")) {
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADTYPE);
        }

        log.info("TOKEN STRING: " + tokenStr);

        try {
            return jwtUtil.validateToken(tokenStr);
        } catch (MalformedJwtException e) {
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.MALFORM);
        } catch (SignatureException e) {
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADSIGN);
        } catch (ExpiredJwtException e) {
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
        }
    }
}
