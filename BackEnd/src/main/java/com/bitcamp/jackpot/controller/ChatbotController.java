package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.dto.ChatbotRequestDTO;
import com.bitcamp.jackpot.service.ChatbotService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/chatbot")
@RequiredArgsConstructor  // 의존성 주입을 위한 생성자 자동 생성
public class ChatbotController {

    private final ChatbotService chatbotService;

    // 챗봇 메시지 전송 API 엔드포인트
    @PostMapping("/send")
    public ResponseEntity<String> sendMessage(@RequestBody ChatbotRequestDTO chatbotRequestDTO) {
        String responseMessage = chatbotService.sendMessage(chatbotRequestDTO.getMessage());
        return ResponseEntity.ok(responseMessage);
    }


}
