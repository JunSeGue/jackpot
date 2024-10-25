package com.bitcamp.jackpot.jwt;

import com.bitcamp.jackpot.dto.RefreshDTO;
import com.bitcamp.jackpot.util.RedisUtil;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

//0.12.3방식
@Component

public class JWTUtil {

    private SecretKey secretKey;
    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username",String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role",String.class);
    }
    // 토큰 만료 여부 확인
    public Boolean isExpired(String token) {
        return getExpiration(token).before(new Date());
    }
    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category",String.class);
    }
    public Date getExpiration(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration();
    }
    //토큰생성
    public String createJwt(String category,String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("category",category)
                .claim("username",username)
                .claim("role",role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }

    public Cookie createCookie(String key ,String value){
        Cookie cookie = new Cookie(key,value);
        cookie.setMaxAge(24*60*60);
        //cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }

    public void addRefreshDTO(String username, String refresh, Long expiredMs, RedisUtil redisUtil){
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshDTO refreshDTO = new RefreshDTO();
        refreshDTO.setUsername(username);
        refreshDTO.setRefresh(refresh);
        refreshDTO.setExpiration(date.toString());

        redisUtil.set(username, refreshDTO, expiredMs.intValue() / (1000 * 60));  // 밀리초를 분 단위로 변환

    }

}
