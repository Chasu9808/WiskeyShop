package com.busanit501.boot501.security.handler;

import com.busanit501.boot501.security.dto.MemberSecurityDTO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Log4j2
@RequiredArgsConstructor
public class CustomSocialLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final PasswordEncoder passwordEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("=====CustomSocialLoginSuccessHandler  onAuthenticationSuccess 확인 ===============================");
        log.info(authentication.getPrincipal());

        MemberSecurityDTO memberSecurityDTO = (MemberSecurityDTO) authentication.getPrincipal();

        String encodePw = memberSecurityDTO.getMpw();
        log.info("패스워드를 변경해주세요. encodePw = memberSecurityDTO.getMpw(); : " + encodePw);

        boolean test1 = memberSecurityDTO.getMpw().equals("1111");
        boolean test2 = passwordEncoder.matches("1111", memberSecurityDTO.getMpw());
        log.info("패스워드 일치 여부1 memberSecurityDTO.getMpw().equals(\"1111\"); : " + test1);
        log.info("패스워드 일치 여부2  passwordEncoder.matches(\"1111\", memberSecurityDTO.getMpw()); : " + test2);

        // 소셜 로그인은 무조건 패스워드를 1111 , 설정
        // 변경이 필요함.
        // 처음에 소셜 로그인으로 최초 로그인시, 사용하는 패스워드 1111 를 사용시
        // 마이페이지 수정페이지로 이동.
        if( memberSecurityDTO.isSocial()
                && memberSecurityDTO.getMpw().equals("1111") || passwordEncoder.matches("1111", memberSecurityDTO.getMpw())){
            log.info("패스워드를 변경해주세요.");
            log.info("회원 정보 변경하는 페이지로 리다이렉트, 마이 페이지가 없음. 일단 수동으로 임의로 변경하기 ");
            log.info(("memberSecurityDTO 확인: " + memberSecurityDTO));
            boolean test3 = memberSecurityDTO.getMpw().equals("1111");
            boolean test4 = passwordEncoder.matches("1111", memberSecurityDTO.getMpw());
            log.info("패스워드 일치 여부3 memberSecurityDTO.getMpw().equals(\"1111\"); : " + test3);
            log.info("패스워드 일치 여부4  passwordEncoder.matches(\"1111\", memberSecurityDTO.getMpw()); : " + test4);
            response.sendRedirect("/member/update");
            return;
        } else {
            // 기본 패스워드 1111를 사용안하고, 변경했다면, 목록 리스트 이동.
            response.sendRedirect("/board/list");
        }
    }
}
