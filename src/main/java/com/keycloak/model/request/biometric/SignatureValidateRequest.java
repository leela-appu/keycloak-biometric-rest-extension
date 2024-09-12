package com.keycloak.model.request.biometric;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SignatureValidateRequest {

    private String email;
    private String signature;
    private String deviceId;

}
