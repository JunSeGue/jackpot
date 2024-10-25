package com.bitcamp.jackpot.config.error.exception;

public class DuplicateResourceException extends RuntimeException {
    private final boolean isDuplicate;

    public DuplicateResourceException(boolean isDuplicate) {
        this.isDuplicate = isDuplicate;
    }

    public boolean getIsDuplicate() {
        return isDuplicate;
    }
}
