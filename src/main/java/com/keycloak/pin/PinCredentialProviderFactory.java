package com.keycloak.pin;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

public class PinCredentialProviderFactory implements CredentialProviderFactory<PinCredentialProvider>, EnvironmentDependentProviderFactory {
    public static final String PROVIDER_ID = "external-secure-pin";

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new PinCredentialProvider(session);
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
