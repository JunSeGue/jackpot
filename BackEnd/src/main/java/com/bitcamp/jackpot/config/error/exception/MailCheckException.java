package com.bitcamp.jackpot.config.error.exception;

import com.bitcamp.jackpot.config.error.ErrorCode;

public class MailCheckException extends BusinessBaseException {
    public MailCheckException(ErrorCode errorCode) {
        super(errorCode);
    }
}
