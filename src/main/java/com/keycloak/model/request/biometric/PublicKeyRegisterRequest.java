package com.keycloak.model.request.biometric;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PublicKeyRegisterRequest {

    private String email;
    private String publicKey;
    private String deviceId;

}
