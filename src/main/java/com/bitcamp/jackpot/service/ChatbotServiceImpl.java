package com.bitcamp.jackpot.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor  // 생성자를 자동으로 생성하여 의존성 주입 처리
public class ChatbotServiceImpl implements ChatbotService {

    private static final String API_URL = "https://4am1thm192.apigw.ntruss.com/custom/v1/16009/36dcafb0c583ab4d5c6ca1029ad2aeeb39811c23270c2ef023e7f50658f7fa1c";
    private static final String SECRET_KEY = "Qnlwc3ZiZXdWYlZIUnFzR3RQdE1zcG9vaEdhVEhMbmk=";

    // ObjectMapper는 JSON 객체를 쉽게 다룰 수 있게 함
    private final ObjectMapper objectMapper = new ObjectMapper();

    // 챗봇 API와 통신하는 메소드
    @Override
    public String sendMessage(String voiceMessage) {
        String chatbotMessage = "";

        try {
            URL url = new URL(API_URL);
            String message = getReqMessage(voiceMessage);
            String encodeBase64String = makeSignature(message, SECRET_KEY);

            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json;UTF-8");
            con.setRequestProperty("X-NCP-CHATBOT_SIGNATURE", encodeBase64String);

            // POST 요청
            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.write(message.getBytes("UTF-8"));
            wr.flush();
            wr.close();

            // 응답 코드 확인
            int responseCode = con.getResponseCode();
            if (responseCode == 200) {
                BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
                StringBuilder response = new StringBuilder();
                String decodedString;
                while ((decodedString = in.readLine()) != null) {
                    response.append(decodedString);
                }
                in.close();

                // JSON 응답에서 description 추출
                chatbotMessage = extractDescription(response.toString());
            } else {
                chatbotMessage = con.getResponseMessage(); // 에러 메시지 처리
            }
        } catch (Exception e) {
            log.error("Exception: " + e);
        }

        return chatbotMessage;
    }

    // HMAC SHA-256 서명 생성
    @Override
    public String makeSignature(String message, String secretKey) {
        String encodeBase64String = "";

        try {
            byte[] secretKeyBytes = secretKey.getBytes("UTF-8");
            SecretKeySpec signingKey = new SecretKeySpec(secretKeyBytes, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(message.getBytes("UTF-8"));
            // java.util.Base64 사용하여 인코딩
            encodeBase64String = Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            log.error("Exception: " + e);
        }

        return encodeBase64String;
    }

    // 요청 메시지 생성 (ObjectMapper를 사용하여 JSON 처리)
    @Override
    public String getReqMessage(String voiceMessage) {
        String requestBody = "";

        try {
            // 최상위 JSON 객체 생성
            ObjectNode obj = objectMapper.createObjectNode();
            long timestamp = new Date().getTime();
            String userId = UUID.randomUUID().toString();

            obj.put("version", "v2");
            obj.put("userId", userId);  // 실제 구현시 고유 ID 사용 필요
            obj.put("timestamp", timestamp);

            // bubbles 객체 생성
            ObjectNode bubblesObj = objectMapper.createObjectNode();
            bubblesObj.put("type", "text");

            // data 객체 생성
            ObjectNode dataObj = objectMapper.createObjectNode();
            dataObj.put("description", voiceMessage);

            bubblesObj.set("data", dataObj);

            // bubbles 배열 생성
            ArrayNode bubblesArray = objectMapper.createArrayNode();
            bubblesArray.add(bubblesObj);

            obj.set("bubbles", bubblesArray);
            obj.put("event", "send");

            // JSON 문자열로 변환
            requestBody = objectMapper.writeValueAsString(obj);

        } catch (Exception e) {
            log.error("Exception: " + e);
        }

        return requestBody;
    }

    // JSON 응답에서 description 필드를 추출하고 JSON 형식으로 반환하는 메소드
    @Override
    public String extractDescription(String jsonResponse) {
        try {
            JsonNode rootNode = objectMapper.readTree(jsonResponse);
            JsonNode bubblesArray = rootNode.path("bubbles");
            if (bubblesArray.isArray() && !bubblesArray.isEmpty()) {
                JsonNode firstBubble = bubblesArray.get(0);
                JsonNode dataNode = firstBubble.path("data");
                String description = dataNode.path("description").asText();

                // JSON 형식으로 message 값 설정
                ObjectNode responseObj = objectMapper.createObjectNode();
                responseObj.put("message", description);

                // JSON 문자열로 변환하여 반환
                return objectMapper.writeValueAsString(responseObj);
            }
        } catch (Exception e) {
            log.error("Exception: " + e);

        }
        return "{\"message\": \"\"}";  // 오류 발생 시 빈 메시지 반환
    }

}
