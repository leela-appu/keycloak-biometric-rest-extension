package com.keycloak.model.request.pin;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PinValidateRequest {

    private String email;
    private String pin;
    private String signature;
    private String deviceId;

}
