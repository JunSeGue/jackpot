package com.bitcamp.jackpot.config.error;

import com.bitcamp.jackpot.config.error.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    protected ResponseEntity<ErrorResponse> handle(HttpRequestMethodNotSupportedException e) {
        log.error("HttpRequestMethodNotSupportedException", e);

        return createErrorResponseEntity(ErrorCode.METHOD_NOT_ALLOWED);
    }

    @ExceptionHandler(BusinessBaseException.class)
    protected ResponseEntity<ErrorResponse> handle(BusinessBaseException e) {
        log.error("BusinessBaseException", e);
        return createErrorResponseEntity(e.getErrorCode());
    }

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<Map<String, Object>> handle(DuplicateResourceException e) {
        Map<String, Object> response = new HashMap<>();
        response.put("isDuplicate", e.getIsDuplicate());

        return new ResponseEntity<>(response, HttpStatus.CONFLICT); // 409 Conflict 응답
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<ErrorResponse> handle(InvalidPasswordException e) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", e.getMessage()); // 예외 메시지
        response.put("errorCode", e.getErrorCode()); // 커스텀 에러 코드

        return createErrorResponseEntity(e.getErrorCode());
    }

    @ExceptionHandler(MemberNotFoundException.class)
    public ResponseEntity<ErrorResponse> handle(MemberNotFoundException e) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", e.getMessage()); // 예외 메시지
        response.put("errorCode", e.getErrorCode()); // 커스텀 에러 코드

        return createErrorResponseEntity(e.getErrorCode());
    }

    @ExceptionHandler(MailCheckException.class)
    public ResponseEntity<ErrorResponse> handle(MailCheckException e) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", e.getMessage()); // 예외 메시지
        response.put("errorCode", e.getErrorCode()); // 커스텀 에러 코드

        return createErrorResponseEntity(e.getErrorCode());
    }



    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ErrorResponse> handle(Exception e) {
        e.printStackTrace();
        log.error("Exception", e);
        return createErrorResponseEntity(ErrorCode.INTERNAL_SERVER_ERROR);
    }

    private ResponseEntity<ErrorResponse> createErrorResponseEntity(ErrorCode errorCode) {
        return new ResponseEntity<>(
                ErrorResponse.of(errorCode),
                errorCode.getHttpStatus());

    }
}
