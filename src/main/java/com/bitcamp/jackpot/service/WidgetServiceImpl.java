package com.bitcamp.jackpot.service;

import com.bitcamp.jackpot.domain.Fund;
import com.bitcamp.jackpot.domain.Member;
import com.bitcamp.jackpot.domain.Orders;
import com.bitcamp.jackpot.dto.FundDTO;
import com.bitcamp.jackpot.dto.MemberDTO;
import com.bitcamp.jackpot.dto.OrdersDTO;
import com.bitcamp.jackpot.jwt.CustomUserDetails;
import com.bitcamp.jackpot.repository.FundRepository;
import com.bitcamp.jackpot.repository.MemberRepository;
import com.bitcamp.jackpot.repository.OrdersRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Service
@Log4j2
@RequiredArgsConstructor
public class WidgetServiceImpl implements WidgetService {

    private final OrdersServiceImpl ordersService;
    private final DogServiceImpl dogService;
    private final MemberRepository memberRepository;
    private final FundRepository fundRepository;
    private final OrdersRepository ordersRepository;
    private final ModelMapper modelMapper;

    @Override
    public ResponseEntity<JSONObject> confirmTossPayments(JSONObject requestData) throws Exception{

        // 클라이언트에서 받은 JSON 요청 바디를 파싱
        String paymentKey = requestData.get("paymentKey") != null ? requestData.get("paymentKey").toString() : null;
        String orderId = requestData.get("orderId") != null ? requestData.get("orderId").toString() : null;
        int amount = requestData.get("amount") != null ? Integer.parseInt(requestData.get("amount").toString()) : 0;
        Boolean isFunding = requestData.get("isFunding") != null && (boolean) requestData.get("isFunding");

        // API 요청에 사용할 JSON 데이터 생성
        JSONObject obj = new JSONObject();
        obj.put("orderId", orderId);
        obj.put("amount", amount);
        obj.put("paymentKey", paymentKey);
        obj.put("isFunding", isFunding); // 펀딩 여부 추가

        // 토스페이먼츠 API 시크릿 키 설정
        String widgetSecretKey = "test_gsk_docs_OaPz8L5KdmQXkzRz3y47BMw6";
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] encodedBytes = encoder.encode((widgetSecretKey + ":").getBytes(StandardCharsets.UTF_8));
        String authorization = "Basic " + new String(encodedBytes);

        URL url = new URL("https://api.tosspayments.com/v1/payments/confirm");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestProperty("Authorization", authorization);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);

        // API 요청 바디 전송
        OutputStream outputStream = connection.getOutputStream();
        outputStream.write(obj.toString().getBytes(StandardCharsets.UTF_8));
        outputStream.flush();
        outputStream.close();

        // 응답 코드 확인
        int code = connection.getResponseCode();
        boolean isSuccess = code == 200;

        InputStream responseStream = isSuccess ? connection.getInputStream() : connection.getErrorStream();
        Reader reader = new InputStreamReader(responseStream, StandardCharsets.UTF_8);

        JSONParser parser = new JSONParser();
        JSONObject jsonObject = (JSONObject) parser.parse(reader);
        responseStream.close();

        if(isSuccess){
            if(isFunding){
                dogService.addFund(
                        FundDTO.builder()
                                .dogId(((Long)requestData.get("dogId")).intValue())
                                .orderId(orderId)
                                .collection(amount)
                                .build()
                );
            }
            else{
                String sProductNames = requestData.get("productNames") != null ? requestData.get("productNames").toString() : null;
                JSONArray productNames = (JSONArray) parser.parse(sProductNames);
                payDataRegistOrder(productNames,orderId);
            }
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            CustomUserDetails ud = (CustomUserDetails) auth.getPrincipal();
            Member member = memberRepository.findByEmail(ud.getUsername()).orElseThrow();
            List<Fund> memberFunds = fundRepository.findAllByMemberId(member.getMemberId());
            List<Orders> memberOrders = ordersRepository.findAllByMemberId(member.getMemberId());
            int memberTotalAmount = memberFunds.stream().mapToInt(Fund::getCollection).sum() +
                    memberOrders.stream().mapToInt(Orders::getTotalPrice).sum();
            if (memberTotalAmount >= 50000){
                member.updateMemberGrade(2);
                memberRepository.save(member);
            }
        }
        return ResponseEntity.status(code).body(jsonObject);
    }

    @Override
    public void payDataRegistOrder(JSONArray jsonArray, String orderId) throws ParseException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails ud = (CustomUserDetails) auth.getPrincipal();
        Member member = memberRepository.findByEmail(ud.getUsername()).orElseThrow();

        JSONParser parser = new JSONParser();

        for (Object o :  jsonArray){
            JSONObject product = (JSONObject) parser.parse(o.toString());
            ordersService.register(
                    OrdersDTO.builder()
                            .orderId(orderId)
                            .shopId(((Long)product.get("shopId")).intValue())
                            .quantity(((Long)product.get("quantity")).intValue())
                            .totalPrice(((Long)product.get("totalProductPrice")).intValue())
                            .deliveryState(0)
                            .memberId(member.getMemberId())
                            .build()
            );
        }
    }
}
