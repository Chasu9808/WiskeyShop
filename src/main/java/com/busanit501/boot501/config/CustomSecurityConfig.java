package com.busanit501.boot501.config;

import com.busanit501.boot501.security.CustomUserDetailsService;
import com.busanit501.boot501.security.filter.APILoginFilter;
import com.busanit501.boot501.security.filter.RefreshTokenFilter;
import com.busanit501.boot501.security.filter.TokenCheckFilter;
import com.busanit501.boot501.security.handler.APILoginSuccessHandler;
import com.busanit501.boot501.security.handler.Custom403Handler;
import com.busanit501.boot501.security.handler.CustomSocialLoginSuccessHandler;
import com.busanit501.boot501.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Log4j2
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity()
@EnableWebSecurity
public class CustomSecurityConfig {

    private final DataSource dataSource;
    private final CustomUserDetailsService customUserDetailsService;
    // IP에서 분당 요청 횟수 제한
    private final RateLimitingFilter rateLimitingFilter;
    // JWT 유틸
    private final JWTUtil jwtUtil;

    // 평문 패스워드를 해시 함수 이용해서 인코딩 해주는 도구 주입.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("시큐리티 동작 확인 ====CustomSecurityConfig======================");

        // =========================
        // 1) AuthenticationManager 설정 (JWT 로그인에서 사용)
        // =========================
        AuthenticationManagerBuilder authBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());

        AuthenticationManager authenticationManager = authBuilder.build();
        http.authenticationManager(authenticationManager);

        // =========================
        // 2) JWT 로그인 필터 (/generateToken)
        // =========================
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);
        apiLoginFilter.setAuthenticationSuccessHandler(apiLoginSuccessHandler());

        // =========================
        // 3) 기존 formLogin / logout / 기본 설정
        // =========================
        http.formLogin(
                formLogin -> formLogin.loginPage("/member/login").permitAll()
        );

        http.logout(
                logout -> logout.logoutUrl("/member/logout").logoutSuccessUrl("/member/login?logout")
        );

        http.formLogin(formLogin ->
                formLogin.defaultSuccessUrl("/", true)
        );

        // 기본은 csrf 설정이 on, 작업시에는 끄고 작업하기.
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());

        // =========================
        // 4) URL 권한 설정
        // =========================
        http.authorizeRequests()
                // 정적 자원 모두 허용.
                .requestMatchers("/css/**", "/js/**", "/images/**", "/images2/**").permitAll()
                // 리스트는 기본으로 다 들어갈 수 있게, 모두 허용
                .requestMatchers("/", "/board/list", "/member/join", "/login", "/member/login",
                        "/joinUser", "/joinForm", "/findAll", "/images/**", "/members/**",
                        "/item/**").permitAll()
                // 로그인 후 확인 하기.
                .requestMatchers("/board/register", "/board/read", "/board/update").authenticated()
                // 관리자만
                .requestMatchers("/admin/**").permitAll()
                // 위의 접근 제어 목록 외의 , 다른 어떤 요청이라도 반드시 인증이 되어야 접근이 된다.
                // .anyRequest().authenticated();
                // 확인용으로 사용하기.
                .anyRequest().permitAll();

        // =========================
        // 5) 403 핸들러 적용
        // =========================
        http.exceptionHandling(
                accessDeny -> accessDeny.accessDeniedHandler(accessDeniedHandler())
        );

        // =========================
        // 6) remember-me 설정 스프링부트 3.x에서는 사용안함
        // =========================
//        http.rememberMe(
//                httpSecurityRememberMeConfigurer ->
//                        httpSecurityRememberMeConfigurer
//                                .key("12345678")
//                                .tokenRepository(persistentTokenRepository())
//                                .userDetailsService(customUserDetailsService)
//                                .tokenValiditySeconds(60 * 60 * 24 * 30)
//        );

        // =========================
        // 7) 카카오 로그인 (세션 방식 유지)
        // =========================
        http.oauth2Login(
                oauthLogin -> oauthLogin.loginPage("/member/login")
                        .successHandler(authenticationSuccessHandler())
        );

        // =========================
        // 8) 필터 체인 구성 (RateLimit + JWT)
        // =========================
        // 8-1) RateLimitingFilter: 모든 요청에 대해 먼저 적용
        http.addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class);

        // 8-2) JWT 로그인 필터 (/generateToken)
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        // 8-3) JWT 토큰 검사 필터 (/api/** 전용)
        http.addFilterBefore(
                new TokenCheckFilter(customUserDetailsService, jwtUtil),
                UsernamePasswordAuthenticationFilter.class
        );

        // 8-4) 리프레시 토큰 필터 (/refreshToken 전용)
        http.addFilterBefore(
                new RefreshTokenFilter("/refreshToken", jwtUtil),
                TokenCheckFilter.class
        );

        // =========================
        // 최종 빌드
        // =========================
        return http.build();
    }

    // 소셜 로그인 후, 후처리 하는 빈등록. (카카오용, 기존 그대로 유지)
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomSocialLoginSuccessHandler(passwordEncoder());
    }

    // JWT 로그인 성공 핸들러 (/generateToken용)
    @Bean
    public AuthenticationSuccessHandler apiLoginSuccessHandler() {
        return new APILoginSuccessHandler(jwtUtil);
    }

    // 자동로그인 설정 2
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }

    // 정적 자원 시큐리티 필터 항목에 제외하기.
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("시큐리티 동작 확인 ====webSecurityCustomizer======================");
        return (web) ->
                web.ignoring()
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    // 사용자 정의한 403 예외 처리
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new Custom403Handler();
    }

}
