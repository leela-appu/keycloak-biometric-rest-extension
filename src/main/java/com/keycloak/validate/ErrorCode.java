package com.keycloak.validate;

import lombok.Getter;

@Getter
public enum ErrorCode {

    EMPTY_EMAIL("Provided Email is null or empty."),
    EMPTY_DEVICE_ID("Provided device id is null or empty."),
    EMPTY_SIGNATURE("Provided signature is null or empty."),
    EMPTY_PUBLIC_KEY("Provided public key is null or empty."),
    EMPTY_PIN("Provided pin is null or empty."),
    INVALID_PIN("Provided pin is invalid.");
    // Add more error codes as needed

    private final String message;

    ErrorCode(String message) {
        this.message = message;
    }

}
