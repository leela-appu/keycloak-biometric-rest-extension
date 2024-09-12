package com.keycloak.pin;

import com.keycloak.util.Constants;
import com.keycloak.util.CredentialProviderUtil;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

public class PinCredentialProvider implements CredentialProvider<PinCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(WebAuthnCredentialProvider.class);
    private final KeycloakSession session;

    public PinCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return PinCredentialModel.TYPE_PIN;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, PinCredentialModel credentialModel) {
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

    public void createPinCredential(UserModel userModel, String securePin, String deviceId, String credentialPublicKey) throws Exception {
        userModel.removeAttribute(Constants.SECURE_PIN);
        userModel.removeAttribute(Constants.IS_SECURE_PIN_REGISTERED);
        PinCredentialModel credentialModel = getCredentialByDeviceId(userModel, deviceId);
        if (credentialModel != null) {
            deleteCredential(session.getContext().getRealm(), userModel, credentialModel.getId());
        }
        PinCredentialModel pinCredentialModel = PinCredentialModel.create(deviceId, CredentialProviderUtil.encodePublicKeyToString(CredentialProviderUtil.parsePublicKey(credentialPublicKey)));
        userModel.setSingleAttribute(Constants.SECURE_PIN, CredentialProviderUtil.pinEncryptOrDecrypt(securePin, true));
        userModel.setSingleAttribute(Constants.IS_SECURE_PIN_REGISTERED, String.valueOf(true));
        createCredential(session.getContext().getRealm(), userModel, pinCredentialModel);
    }

    public void addDeviceCredential(UserModel userModel, String deviceId, String credentialPublicKey) throws Exception {
        PinCredentialModel credentialModel = getCredentialByDeviceId(userModel, deviceId);
        if (credentialModel != null) {
            deleteCredential(session.getContext().getRealm(), userModel, credentialModel.getId());
        }
        PinCredentialModel pinCredentialModel = PinCredentialModel.create(deviceId, CredentialProviderUtil.encodePublicKeyToString(CredentialProviderUtil.parsePublicKey(credentialPublicKey)));
        createCredential(session.getContext().getRealm(), userModel, pinCredentialModel);
    }

    public PinCredentialModel getCredentialByDeviceId(UserModel userModel, String deviceId) {
        List<PinCredentialModel> pinCredentialModelList = userModel.credentialManager().getStoredCredentialsByTypeStream(getType())
                .map(credentialModel -> {
                    PinCredentialModel credModel = PinCredentialModel.createFromCredentialModel(credentialModel);
                    return credModel.getPinCredentialData().getDeviceId().equals(deviceId) ? credModel : null;
                }).filter(Objects::nonNull).collect(Collectors.toList());
        return pinCredentialModelList.isEmpty() ? null : pinCredentialModelList.get(0);
    }

    public void deletePinCredential(UserModel userModel) {
        userModel.removeAttribute(Constants.SECURE_PIN);
        userModel.removeAttribute(Constants.IS_SECURE_PIN_REGISTERED);
        userModel.credentialManager().getStoredCredentialsByTypeStream(getType()).forEach(pinModel ->
                Optional.ofNullable(pinModel).ifPresent(model -> deleteCredential(session.getContext().getRealm(), userModel, model.getId())));
    }

    public PinCredentialModel getPinCredential(UserModel userModel) {
        List<CredentialModel> pins = userModel.credentialManager().getStoredCredentialsByTypeStream(getType()).collect(Collectors.toList());
        if (pins.isEmpty()) return null;
        return PinCredentialModel.createFromCredentialModel(pins.get(0));
    }

    public boolean verifyPin(UserModel userModel, String pin) throws Exception {
        return Integer.parseInt(pin) == Integer.parseInt(CredentialProviderUtil.pinEncryptOrDecrypt(userModel.getFirstAttribute(Constants.SECURE_PIN), false).trim());
    }

    @Override
    public PinCredentialModel getCredentialFromModel(CredentialModel model) {
        return PinCredentialModel.createFromCredentialModel(model);
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
        return getPinCredential(user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        return false;
    }
}
