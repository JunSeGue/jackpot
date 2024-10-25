package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.config.error.ErrorCode;
import com.bitcamp.jackpot.config.error.exception.MailCheckException;
import com.bitcamp.jackpot.config.error.exception.MemberNotFoundException;
import com.bitcamp.jackpot.dto.VerificationCodeDTO;
import com.bitcamp.jackpot.util.RedisUtil;
import com.bitcamp.jackpot.repository.MemberRepository;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;


@Service
@Slf4j
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {

    private final JavaMailSender javaMailSender;
    private final RedisUtil redisUtil;
    private final MemberRepository memberRepository;


    public void checkVerificationCode(VerificationCodeDTO verificationCodeDTO) {

        String code = verificationCodeDTO.getCode();
        String email = verificationCodeDTO.getEmail();

        try {
            // Redis에서 인증 코드 비교, 일치하지 않으면 false 반환
            if (!redisUtil.isValueEqual(email, code)) {
                throw new RuntimeException();
            }
            else redisUtil.delete(email);
        } catch (Exception e) {
            throw new MailCheckException(ErrorCode.INVALID_INPUT_VALUE);
        }
    }

   public String createCode() throws NoSuchAlgorithmException {
        int length = 6;

        Random random = SecureRandom.getInstanceStrong();
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            builder.append(random.nextInt(10));
        }
        return builder.toString();
    }



    public void sendSimpleMailMessage(String email) {
        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        try {
            // 이메일 형식 검증
            validateEmail(email);

            // 메일을 받을 수신자 설정
            simpleMailMessage.setTo(email);
            // 메일의 제목 설정
            simpleMailMessage.setSubject("ppyppy 인증번호");

            // 인증 코드 생성
            String code = createCode();
            simpleMailMessage.setText("인증번호 : " + code);

            // 메일 발송
            javaMailSender.send(simpleMailMessage);
            log.info("메일 발송 성공! 대상: {}", email);

            // Redis에 인증 코드 저장
            saveVerificationCodeToRedis(email, code);

        } catch (Exception e) {
            log.error("메일 서비스 중 오류 발생! 대상: {}", email, e);
            throw new MailSendException("메일 발송 및 인증 코드 저장 중 오류가 발생했습니다.", e);
        }
    }

    private void saveVerificationCodeToRedis(String email, String code) {
        redisUtil.set(email, code, 3);
        log.info("Redis에 인증 코드 저장 성공! 대상: {}, 만료 시간: {}분", email, 3);
    }

    private void validateEmail(String email) {
        // 이메일 형식 검증 로직
        if (email == null || !email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            throw new IllegalArgumentException("유효하지 않은 이메일 형식입니다.");
        }
    }


}
