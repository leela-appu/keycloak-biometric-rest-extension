package com.keycloak.model.request.pin;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class DeviceRegisterRequest {

    private String email;
    private String publicKey;
    private String deviceId;

}
