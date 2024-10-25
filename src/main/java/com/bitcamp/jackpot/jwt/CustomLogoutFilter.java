package com.bitcamp.jackpot.jwt;

import com.bitcamp.jackpot.service.LogoutService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final LogoutService logoutService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // 로그아웃 요청이 아닌 경우 다음 필터로 이동
        String requestUri = request.getRequestURI();
        if (!requestUri.endsWith("/member/signOut")) {
            filterChain.doFilter(request, response);
            return;
        }

        // POST 요청이 아니면 다음 필터로 이동
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 로그아웃 처리 (서비스 호출로 대체)
        try {
            logoutService.logout(request, response);
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (IllegalArgumentException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
