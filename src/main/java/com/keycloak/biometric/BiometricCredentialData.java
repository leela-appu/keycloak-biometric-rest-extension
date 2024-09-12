package com.keycloak.biometric;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class BiometricCredentialData {
    private final String deviceId;
    private final String credentialPublicKey;

    @JsonCreator
    public BiometricCredentialData(@JsonProperty("deviceId") String deviceId,
                                  @JsonProperty("credentialPublicKey") String credentialPublicKey) {
        this.deviceId = deviceId;
        this.credentialPublicKey = credentialPublicKey;
    }

    @Override
    public String toString() {
        return "BiometricCredentialData { " +
                "deviceId='" + deviceId + '\'' +
                ", credentialPublicKey='" + credentialPublicKey + '\'' +
                " }";
    }
}
