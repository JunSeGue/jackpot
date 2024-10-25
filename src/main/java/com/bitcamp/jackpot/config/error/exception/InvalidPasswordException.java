package com.bitcamp.jackpot.config.error.exception;

import com.bitcamp.jackpot.config.error.ErrorCode;

public class InvalidPasswordException extends BusinessBaseException {


    public InvalidPasswordException(String message, ErrorCode errorCode) {
        super(message, errorCode);
    }
}
