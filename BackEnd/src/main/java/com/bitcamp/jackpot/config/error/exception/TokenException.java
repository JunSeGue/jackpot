package com.bitcamp.jackpot.config.error.exception;

import com.bitcamp.jackpot.config.error.ErrorCode;

public class TokenException extends BusinessBaseException {

    public TokenException(final String message) {
        super(ErrorCode.INAVLID_TOKEN);

    }
    public TokenException(final String message, ErrorCode errorCode) {
        super(message,errorCode);
    }
}
