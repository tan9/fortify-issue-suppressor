package com.cht.fortify.audit;

public class IssueSuppressorException extends RuntimeException {

    public IssueSuppressorException(String message) {
        super(message);
    }

    public IssueSuppressorException(String message, Throwable cause) {
        super(message, cause);
    }

    public IssueSuppressorException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
