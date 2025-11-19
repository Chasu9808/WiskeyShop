package com.busanit501.boot501.security.handler;

import com.busanit501.boot501.util.JWTUtil;
import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class APILoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        log.info("APILoginSuccessHandler - Login Success");
        log.info("authentication.getName(): " + authentication.getName());

        Map<String, Object> claim = Map.of("username", authentication.getName());

        String accessToken = jwtUtil.generateToken(claim, 1);   // 1일
        String refreshToken = jwtUtil.generateToken(claim, 30); // 30일

        Gson gson = new Gson();

        Map<String, String> keyMap = Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken,
                "username", authentication.getName()
        );

        String jsonStr = gson.toJson(keyMap);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().println(jsonStr);
    }
}
