package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.config.error.exception.TokenException;
import com.bitcamp.jackpot.jwt.JWTUtil;
import com.bitcamp.jackpot.util.RedisUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class LogoutServiceImp implements LogoutService {

    private final JWTUtil jwtUtil;
    private final RedisUtil redisUtil;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {

        // get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refresh")) {
                    refresh = cookie.getValue();
                }
            }
        }

        if (refresh == null) {
            throw new TokenException("Refresh token is missing.");
        }

        // Token validation
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            throw new TokenException("Refresh token has expired.");
        }
        // Verify token category
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            throw new TokenException("Invalid token category.");
        }

        // DB에서 토큰 존재 여부 확인
        String username = jwtUtil.getUsername(refresh);
        if (!redisUtil.hasKey(username)) {
            throw new TokenException("Refresh token not found.");
        }

        // 토큰 삭제 (DB 및 쿠키)
        redisUtil.delete(username);
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
//        cookie.setSecure(true);
        cookie.setHttpOnly(true);

        response.addCookie(cookie);


        String accessToken = request.getHeader("Authorization");

            accessToken = accessToken.substring(7);

            Date expirationDate = jwtUtil.getExpiration(accessToken);
            Long expirationMs = expirationDate.getTime()-System.currentTimeMillis();  // Date를 밀리초 단위의 Long으로 변환
            redisUtil.setBlackList(accessToken, "access_token", expirationMs);


    }
}
