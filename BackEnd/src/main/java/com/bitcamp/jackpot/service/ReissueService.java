package com.bitcamp.jackpot.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import java.io.IOException;

public interface ReissueService {
    ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) throws IOException;

}
