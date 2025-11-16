package com.busanit501.boot501.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalTime;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
//    이 필터는 각 클라이언트 IP 주소의 요청 수를 추적합니다.
//    요청 횟수와 타임스탬프를 저장하기 위해 메모리 내 캐시('ConcurrentHashMap')를 사용합니다.
//    TIME_WINDOW당 요청 수를 MAX_REQUESTS로 제한합니다.
//    속도 제한을 초과하면 429 상태 코드를 반환합니다.
public class RateLimitingFilter extends OncePerRequestFilter {

    private final ConcurrentMap<String, RateLimit> rateLimitCache = new ConcurrentHashMap<>();
    // 테스트 중이라, 일단 높게
    private static final int MAX_REQUESTS = 200;
    private static final Duration TIME_WINDOW = Duration.ofMinutes(1);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String clientIp = getClientIp(request);

        RateLimit rateLimit = rateLimitCache.computeIfAbsent(clientIp, k -> new RateLimit(MAX_REQUESTS, TIME_WINDOW));

        if (rateLimit.isAllowed()) {
            filterChain.doFilter(request, response);
        } else {
            long retryAfterSeconds = rateLimit.getRetryAfterSeconds();
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
            response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), "Too many requests. Please try again later.");
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    private static class RateLimit {
        private final int maxRequests;
        private final Duration timeWindow;
        private int requestCount;
        private LocalTime windowStart;

        public RateLimit(int maxRequests, Duration timeWindow) {
            this.maxRequests = maxRequests;
            this.timeWindow = timeWindow;
            this.requestCount = 0;
            this.windowStart = LocalTime.now();
        }

        public synchronized boolean isAllowed() {
            LocalTime now = LocalTime.now();
            if (Duration.between(windowStart, now).compareTo(timeWindow) > 0) {
                requestCount = 0;
                windowStart = now;
            }
            requestCount++;
            return requestCount <= maxRequests;
        }

        public synchronized long getRetryAfterSeconds() {
            LocalTime now = LocalTime.now();
            Duration elapsed = Duration.between(windowStart, now);
            if (elapsed.compareTo(timeWindow) > 0) {
                return 0;
            } else {
                return timeWindow.minus(elapsed).getSeconds();
            }
        }
    }
}