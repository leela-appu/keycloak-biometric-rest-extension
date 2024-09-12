package com.keycloak.pin;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class PinCredentialData {
    private final String securePin;
    private final String deviceId;
    private final String credentialPublicKey;

    @JsonCreator
    public PinCredentialData(@JsonProperty("deviceId") String deviceId,
                             @JsonProperty("credentialPublicKey") String credentialPublicKey,
                             @JsonProperty("securePin") String securePin) {
        this.deviceId = deviceId;
        this.securePin = securePin;
        this.credentialPublicKey = credentialPublicKey;
    }

    @Override
    public String toString() {
        return "PinCredentialData { " +
                ", deviceId='" + deviceId + '\'' +
                ", securePin='" + securePin + '\'' +
                ", credentialPublicKey='" + credentialPublicKey + '\'' +
                " }";
    }
}
