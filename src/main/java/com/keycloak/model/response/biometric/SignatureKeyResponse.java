package com.keycloak.model.response.biometric;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SignatureKeyResponse {
    private String email;
    private String signatureKey;

    public SignatureKeyResponse(String email, String signatureKey) {
        this.email = email;
        this.signatureKey = signatureKey;
    }
}
