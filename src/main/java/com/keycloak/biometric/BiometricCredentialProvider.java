package com.keycloak.biometric;

import com.keycloak.util.CredentialProviderUtil;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class BiometricCredentialProvider implements CredentialProvider<BiometricCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(WebAuthnCredentialProvider.class);
    private final KeycloakSession session;

    public BiometricCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return BiometricCredentialModel.TYPE_BIOMETRIC;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, BiometricCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return user.credentialManager().createStoredCredential(credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        logger.debugv("Delete WebAuthn credential. username = {0}, credentialId = {1}", user.getUsername(), credentialId);
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    public void createBiometricCredential(UserModel userModel, String deviceId, String credentialPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BiometricCredentialModel credentialModel = getCredentialByDeviceId(userModel, deviceId);
        if (credentialModel != null) {
            deleteCredential(session.getContext().getRealm(), userModel, credentialModel.getId());
        }
        BiometricCredentialModel biometricCredentialModel = BiometricCredentialModel.create(deviceId, CredentialProviderUtil.encodePublicKeyToString(CredentialProviderUtil.parsePublicKey(credentialPublicKey)));
        createCredential(session.getContext().getRealm(), userModel, biometricCredentialModel);
    }

    public boolean deleteBiometricCredential(UserModel userModel, String deviceId) {
        BiometricCredentialModel credentialModel = getCredentialByDeviceId(userModel, deviceId);
        if (credentialModel != null) {
            return deleteCredential(session.getContext().getRealm(), userModel, credentialModel.getId());
        }
        return false;
    }

    public BiometricCredentialModel getCredentialByDeviceId(UserModel userModel, String deviceId) {
        List<BiometricCredentialModel> biometricCredentialModelList = userModel.credentialManager().getStoredCredentialsByTypeStream(getType())
                .map(credentialModel -> {
                    BiometricCredentialModel credModel = BiometricCredentialModel.createFromCredentialModel(credentialModel);
                    return credModel.getBiometricCredentialData().getDeviceId().equals(deviceId) ? credModel : null;
                }).filter(Objects::nonNull).collect(Collectors.toList());
        return biometricCredentialModelList.isEmpty() ? null : biometricCredentialModelList.get(0);
    }

    @Override
    public BiometricCredentialModel getCredentialFromModel(CredentialModel model) {
        return BiometricCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return null;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return false;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        return false;
    }

}
