package com.keycloak.biometric;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

public class BiometricCredentialProviderFactory implements CredentialProviderFactory<BiometricCredentialProvider>, EnvironmentDependentProviderFactory {
    public static final String PROVIDER_ID = "external-biometric";

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new BiometricCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isSupported() {
        return false;
    }
}
