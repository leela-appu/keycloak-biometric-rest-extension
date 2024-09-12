package com.keycloak.model.request.biometric;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PublicKeyRemoveRequest {

    private String email;
    private String deviceId;

}
