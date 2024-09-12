package com.keycloak.biometric;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class BiometricResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final EventBuilder eventBuilder;

    BiometricResourceProvider(KeycloakSession session, EventBuilder eventBuilder) {
        this.session = session;
        this.eventBuilder = eventBuilder;
    }
    @Override
    public Object getResource() {
        return new BiometricResource(session, eventBuilder);
    }

    @Override
    public void close() {}

}
