package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.dto.VerificationCodeDTO;

import java.security.NoSuchAlgorithmException;

public interface MailService {

     void checkVerificationCode(VerificationCodeDTO verificationCodeDTO);
     String createCode() throws NoSuchAlgorithmException;
     void sendSimpleMailMessage(String email);



}
