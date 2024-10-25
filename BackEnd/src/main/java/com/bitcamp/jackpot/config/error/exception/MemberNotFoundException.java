package com.bitcamp.jackpot.config.error.exception;

import com.bitcamp.jackpot.config.error.ErrorCode;


public class MemberNotFoundException extends NotFoundException {
    public MemberNotFoundException() {
        super(ErrorCode.MEMBER_NOT_FOUND);
    }

    public MemberNotFoundException(final String message) {
        super(message,ErrorCode.MEMBER_NOT_FOUND);

    }


}
