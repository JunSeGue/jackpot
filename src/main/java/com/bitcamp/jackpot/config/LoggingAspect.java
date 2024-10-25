package com.bitcamp.jackpot.config;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class LoggingAspect {

    private static final Logger log = LoggerFactory.getLogger(LoggingAspect.class);

    // ThreadLocal을 사용하여 예외가 로깅되었는지 추적
    private static final ThreadLocal<Boolean> exceptionLogged = ThreadLocal.withInitial(() -> false);

    // 컨트롤러에서 요청이 들어올 때 로깅
    @Before("execution(* com.bitcamp.jackpot.controller..*(..))")
    public void logControllerRequest(JoinPoint joinPoint) {
        log.info("컨트롤러 요청: {}.{}()",
                joinPoint.getSignature().getDeclaringTypeName(),
                joinPoint.getSignature().getName());
    }

    // 컨트롤러에서 요청이 리턴될 때 로깅
    @AfterReturning(pointcut = "execution(* com.bitcamp.jackpot.controller..*(..))", returning = "result")
    public void logControllerResponse(JoinPoint joinPoint, Object result) {
        log.info("컨트롤러 응답: {}.{}(), 반환값: {}",
                joinPoint.getSignature().getDeclaringTypeName(),
                joinPoint.getSignature().getName(),
                result);
    }

    // 서비스 메서드 실행 후 로깅
    @AfterReturning(pointcut = "execution(* com.bitcamp.jackpot.service..*(..))", returning = "result")
    public void logAfterServiceMethod(JoinPoint joinPoint, Object result) {
        log.info("서비스 메서드 종료: {}.{}(), 반환값: {}",
                joinPoint.getSignature().getDeclaringTypeName(),
                joinPoint.getSignature().getName(),
                result);
    }

    // 전역 예외 처리기에서 리턴 시 로깅
    @AfterReturning(pointcut = "execution(* com.bitcamp.jackpot.config.error.GlobalExceptionHandler..*(..))", returning = "result")
    public void logGlobalExceptionHandlerReturn(JoinPoint joinPoint, Object result) {
        log.info("전역 예외 처리기 리턴: {}.{}(), 반환값: {}",
                joinPoint.getSignature().getDeclaringTypeName(),
                joinPoint.getSignature().getName(),
                result);
    }

    // 서비스 메서드에서 예외 발생 시 로깅
    @AfterThrowing(pointcut = "execution(* com.bitcamp.jackpot.service..*(..))", throwing = "error")
    public void logServiceException(JoinPoint joinPoint, Throwable error) {
        if (!exceptionLogged.get()) {
            log.error("서비스 메서드 예외: {}.{}(), 예외 메시지: {}",
                    joinPoint.getSignature().getDeclaringTypeName(),
                    joinPoint.getSignature().getName(),
                    error.getMessage(), error);
            exceptionLogged.set(true); // 예외가 로깅되었음을 표시
        }
    }

    // 전역 예외 처리기에서 예외 발생 시 로깅
    @AfterThrowing(pointcut = "execution(* com.bitcamp.jackpot.config.error.GlobalExceptionHandler..*(..))", throwing = "error")
    public void logGlobalExceptionHandler(JoinPoint joinPoint, Throwable error) {
        if (!exceptionLogged.get()) {
            log.error("전역 예외 처리기에서 예외 발생: {}.{}(), 예외 메시지: {}",
                    joinPoint.getSignature().getDeclaringTypeName(),
                    joinPoint.getSignature().getName(),
                    error.getMessage(), error);
            exceptionLogged.set(true); // 예외가 로깅되었음을 표시
        }
    }

    // 모든 메서드 실행 후 예외 상태 초기화
    @After("execution(* com.bitcamp.jackpot..*(..))")
    public void resetExceptionLoggedAfter() {
        resetExceptionLogged();
    }

    // 예외 상태 초기화
    public static void resetExceptionLogged() {
        exceptionLogged.remove();
    }
}
