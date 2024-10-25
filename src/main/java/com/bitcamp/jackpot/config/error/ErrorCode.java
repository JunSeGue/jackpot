package com.bitcamp.jackpot.config.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;
@AllArgsConstructor
@Getter
public enum ErrorCode {
    INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST,"E1","올바르지 않은 입력값입니다."),
    METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED,"E2","잘못된 HTTP 메서드를 호출했습니다."),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR,"E3","서버 에러가 발생했습니다."),
    NOT_FOUND(HttpStatus.NOT_FOUND,"E4","존재하지 않는 Entity 입니다."),
    MEMBER_NOT_FOUND(HttpStatus.NOT_FOUND,"A1","존재하지 않는 MEMBER 입니다."),
    CONFLICT(HttpStatus.CONFLICT,"E5","이미 존재합니다."), //409
    DATABASE_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "E6", "Database 에러입니다."),
    INAVLID_TOKEN(HttpStatus.UNAUTHORIZED,"U2","유효하지않은 토큰입니다");

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;


}
