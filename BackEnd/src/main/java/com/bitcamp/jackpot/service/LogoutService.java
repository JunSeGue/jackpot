package com.bitcamp.jackpot.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface LogoutService {
    void logout(HttpServletRequest request, HttpServletResponse response);
}
