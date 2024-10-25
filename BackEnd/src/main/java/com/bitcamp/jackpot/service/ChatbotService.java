package com.bitcamp.jackpot.service;

public interface ChatbotService {
    // 챗봇 API와 통신하는 메소드
    String sendMessage(String voiceMessage);

    // HMAC SHA-256 서명 생성
    String makeSignature(String message, String secretKey);

    // 요청 메시지 생성 (ObjectMapper를 사용하여 JSON 처리)
    String getReqMessage(String voiceMessage);

    // JSON 응답에서 description 필드를 추출하고 JSON 형식으로 반환하는 메소드
    String extractDescription(String jsonResponse);
}
