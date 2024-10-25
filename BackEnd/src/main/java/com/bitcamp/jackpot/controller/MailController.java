package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.dto.VerificationCodeDTO;
import com.bitcamp.jackpot.service.MailServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
public class MailController {

    private final MailServiceImpl mailService;


    @GetMapping("/sendEmail")
    public ResponseEntity<String> sendSimpleMailMessage(@RequestParam String email) {
        mailService.sendSimpleMailMessage(email);
        return ResponseEntity.ok("메일이 성공적으로 송신 되었습니다.");
    }
    @PostMapping("/checkVerificationCode")
    public ResponseEntity<String> checkVerificationCode(@RequestBody VerificationCodeDTO verificationCodeDTO) {
            System.out.println(verificationCodeDTO.getCode()+verificationCodeDTO.getEmail());
           mailService.checkVerificationCode(verificationCodeDTO);
            return  ResponseEntity.ok("인증 성공");
        }

}
