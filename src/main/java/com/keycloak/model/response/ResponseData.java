package com.keycloak.model.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ResponseData {
    private int code;
    private String message;

    public ResponseData(int code, String message) {
        this.code = code;
        this.message = message;
    }
}
