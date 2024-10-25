package com.bitcamp.jackpot.controller;

import com.bitcamp.jackpot.service.WidgetService;
import lombok.RequiredArgsConstructor;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class WidgetController {

    private final WidgetService widgetService;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @PostMapping("/confirm")
    public ResponseEntity<JSONObject> confirmPayment(@RequestBody String jsonBody) throws Exception {
        System.out.println(jsonBody);
        JSONParser parser = new JSONParser();
        JSONObject requestData = (JSONObject) parser.parse(jsonBody);

        // 결과 반환
        return widgetService.confirmTossPayments(requestData);
    }
}
