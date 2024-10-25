package com.bitcamp.jackpot.service;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;
import org.springframework.http.ResponseEntity;

public interface WidgetService {
    ResponseEntity<JSONObject> confirmTossPayments(JSONObject jsonObject) throws Exception;
    void payDataRegistOrder(JSONArray jsonObject, String orderId) throws ParseException;
}
