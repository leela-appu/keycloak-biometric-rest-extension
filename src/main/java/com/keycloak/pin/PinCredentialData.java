package com.keycloak.pin;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class PinCredentialData {
    private final String deviceId;
    private final String credentialPublicKey;

    @JsonCreator
    public PinCredentialData(@JsonProperty("deviceId") String deviceId,
                             @JsonProperty("credentialPublicKey") String credentialPublicKey) {
        this.deviceId = deviceId;
        this.credentialPublicKey = credentialPublicKey;
    }

    @Override
    public String toString() {
        return "PinCredentialData { " +
                ", deviceId='" + deviceId + '\'' +
                ", credentialPublicKey='" + credentialPublicKey + '\'' +
                " }";
    }
}
