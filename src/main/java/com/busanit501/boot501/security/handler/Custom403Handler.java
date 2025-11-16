package com.busanit501.boot501.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

@Log4j2
// 403 접근 권한 예외 발생시 예외처리 -> 똑바로 로그인 하고 이용하세요.
public class Custom403Handler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.info("동작 여부 확인 ,Custom403Handler============ ");
        response.setStatus(HttpStatus.FORBIDDEN.value());

        // 전달시, JSON 인지 여부에 따라 경우의수 2가지.
        // RestController 데이터 만 전달하는지 여부에따라(JSON 으로 전달해서)분리
        String contentType = request.getHeader("Content-Type");
        boolean jsonRequest = contentType.startsWith("application/json");
        log.info("isJson JSON 맞니? : " + jsonRequest);

        // 일반 request 인경우와, JSON 인 경우 2가지.
        // 일반 request
        if(!jsonRequest) {
            response.sendRedirect("/member/login?error=ACCESS_DENIED");
        }
    }
}
