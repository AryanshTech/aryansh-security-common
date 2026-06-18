package com.aryansh.security.exception;

import org.springframework.http.HttpStatus;

public class ConflictException extends ApiException {

    public ConflictException(String message) {
        super("CONFLICT", message, HttpStatus.CONFLICT);
    }
}
