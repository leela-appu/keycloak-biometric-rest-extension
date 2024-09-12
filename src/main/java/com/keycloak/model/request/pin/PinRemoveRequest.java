package com.keycloak.model.request.pin;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PinRemoveRequest {

    private String email;
    private String deviceId;
    
}
