package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.jwt.JWTUtil;
import com.bitcamp.jackpot.util.RedisUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Service
public class ReissueServiceImp implements ReissueService {
    private final JWTUtil jwtUtil;
    private final RedisUtil redisUtil;

    @Override
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) throws IOException {
    //get refresh token
    String refresh = null;
    Cookie[] cookies = request.getCookies();

        System.out.println(Arrays.toString(cookies));

        for (Cookie cookie : cookies) {
            if (cookie == null) {

                return new ResponseEntity<>("no cookies found", HttpStatus.BAD_REQUEST);
            }

        if (cookie.getName().equals("refresh")) {

            refresh = cookie.getValue();
            break;
        }
    }

        if (refresh == null) {

        //response status code
        return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
    }

    //expired check
        try {
        jwtUtil.isExpired(refresh);
    } catch (ExpiredJwtException e) {

        //response status code
        return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
    }

    // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
    String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {

        //response status code
        return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
    }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // Redis에서 refresh token이 존재하는지 확인
        Boolean isExist = redisUtil.hasKey(username);
        if (!isExist) {
            // response body
            return new ResponseEntity<>("invalid refresh token2", HttpStatus.BAD_REQUEST);
        }



    //make new JWT
    String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
    String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        redisUtil.delete(username);

        jwtUtil.addRefreshDTO(username, newRefresh, 86400000L,redisUtil);

        //response
        response.addCookie(jwtUtil.createCookie("refresh", newRefresh));
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> tokenResponse = new HashMap<>();
        tokenResponse.put("access", newAccess);

        objectMapper.writeValue(response.getWriter(), tokenResponse);


        return new ResponseEntity<>(HttpStatus.OK);
    }

}
