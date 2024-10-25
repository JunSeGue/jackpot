package com.bitcamp.jackpot.config.error.exception;

import com.bitcamp.jackpot.config.error.ErrorCode;

public class DatabaseException extends BusinessBaseException {
    public DatabaseException() {
        super(ErrorCode.INTERNAL_SERVER_ERROR);
    }
    public DatabaseException(ErrorCode errorCode) {
        super(errorCode);
    }
}
