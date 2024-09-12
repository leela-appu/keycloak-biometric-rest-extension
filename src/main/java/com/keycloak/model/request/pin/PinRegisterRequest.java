package com.keycloak.model.request.pin;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PinRegisterRequest {

    private String email;
    private String pin;
    private String publicKey;
    private String deviceId;

}
