package com.keycloak.pin;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class PinCredentialModel extends CredentialModel {
    // Credential type used for WebAuthn two factor credentials
    public static final String TYPE_PIN = "pin";

    private final PinCredentialData credentialData;
    private final PinSecretData secretData;

    private PinCredentialModel(PinCredentialData credentialData, PinSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
        setType(TYPE_PIN);
    }

    public static PinCredentialModel create(String deviceId, String credentialPublicKey) {
        PinCredentialData credentialData = new PinCredentialData(deviceId, credentialPublicKey);
        PinSecretData secretData = new PinSecretData();
        PinCredentialModel credentialModel = new PinCredentialModel(credentialData, secretData);
        credentialModel.fillCredentialModelFields();
        return credentialModel;
    }

    public static PinCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            PinCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), PinCredentialData.class);
            PinSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), PinSecretData.class);
            return getPinCredentialModel(credentialModel, credentialData, secretData);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static PinCredentialModel getPinCredentialModel(CredentialModel credentialModel, PinCredentialData credentialData, PinSecretData secretData) {
        PinCredentialModel pinCredentialModel = new PinCredentialModel(credentialData, secretData);
        pinCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
        pinCredentialModel.setId(credentialModel.getId());
        pinCredentialModel.setType(credentialModel.getType());
        pinCredentialModel.setSecretData(credentialModel.getSecretData());
        pinCredentialModel.setCredentialData(credentialModel.getCredentialData());
        return pinCredentialModel;
    }

    public PinCredentialData getPinCredentialData() {
        return credentialData;
    }

    public PinSecretData getBiometricSecretData() {
        return secretData;
    }

    private void fillCredentialModelFields() {
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData(JsonSerialization.writeValueAsString(secretData));
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return "PinCredentialModel { " +
                getType() +
                ", " + credentialData +
                ", " + secretData +
                " }";
    }
}
