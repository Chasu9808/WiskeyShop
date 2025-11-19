package com.busanit501.boot501.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class GlobalUserAdvice {

    // 모든 컨트롤러에 공통으로 "user" 모델을 추가
    @ModelAttribute("user")
    public UserDetails addUser(@AuthenticationPrincipal UserDetails user) {
        // 로그인 안 했으면 null 반환 → th:if 에서 자동으로 걸러짐
        return user;
    }
}