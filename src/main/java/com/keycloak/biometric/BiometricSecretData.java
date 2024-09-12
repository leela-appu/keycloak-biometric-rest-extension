package com.keycloak.biometric;

import com.fasterxml.jackson.annotation.JsonCreator;

public class BiometricSecretData {

    @JsonCreator
    public BiometricSecretData() {
    }
    
    @Override
    public String toString() {
        return "BiometricSecretData {}";
    }
}
