package com.bitcamp.jackpot.config.error.exception;

import com.bitcamp.jackpot.config.error.ErrorCode;

public class NotFoundException extends BusinessBaseException {
    public NotFoundException(ErrorCode errorCode) {
        super(errorCode.getMessage(),errorCode);
    }

    public NotFoundException() {
        super(ErrorCode.NOT_FOUND);
    }


    public NotFoundException(String message, ErrorCode errorCode) {
        super(message, errorCode);
    }
}