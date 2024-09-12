package com.keycloak.pin;

import com.fasterxml.jackson.annotation.JsonCreator;

public class PinSecretData {

    @JsonCreator
    public PinSecretData() {
    }
    
    @Override
    public String toString() {
        return "PinSecretData {}";
    }
}
