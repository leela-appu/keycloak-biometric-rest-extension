package com.keycloak.biometric;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class BiometricCredentialModel extends CredentialModel {
    // Credential type used for WebAuthn two factor credentials
    public static final String TYPE_BIOMETRIC = "biometric";

    private final BiometricCredentialData credentialData;
    private final BiometricSecretData secretData;

    private BiometricCredentialModel(BiometricCredentialData credentialData, BiometricSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
        setType(TYPE_BIOMETRIC);
    }

    public static BiometricCredentialModel create(String deviceId, String credentialPublicKey) {
        BiometricCredentialData credentialData = new BiometricCredentialData(deviceId, credentialPublicKey);
        BiometricSecretData secretData = new BiometricSecretData();
        BiometricCredentialModel credentialModel = new BiometricCredentialModel(credentialData, secretData);
        credentialModel.fillCredentialModelFields();
        return credentialModel;
    }

    public static BiometricCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            BiometricCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), BiometricCredentialData.class);
            BiometricSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), BiometricSecretData.class);
            return getBiometricCredentialModel(credentialModel, credentialData, secretData);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static BiometricCredentialModel getBiometricCredentialModel(CredentialModel credentialModel, BiometricCredentialData credentialData, BiometricSecretData secretData) {
        BiometricCredentialModel biometricCredentialModel = new BiometricCredentialModel(credentialData, secretData);
        biometricCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
        biometricCredentialModel.setId(credentialModel.getId());
        biometricCredentialModel.setType(credentialModel.getType());
        biometricCredentialModel.setSecretData(credentialModel.getSecretData());
        biometricCredentialModel.setCredentialData(credentialModel.getCredentialData());
        return biometricCredentialModel;
    }

    public BiometricCredentialData getBiometricCredentialData() {
        return credentialData;
    }

    public BiometricSecretData getBiometricSecretData() {
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
        return "BiometricCredentialModel { " +
                getType() +
                ", " + credentialData +
                ", " + secretData +
                " }";
    }
}
