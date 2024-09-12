package com.keycloak.pin;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class PinResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final EventBuilder eventBuilder;

    PinResourceProvider(KeycloakSession session, EventBuilder eventBuilder) {
        this.session = session;
        this.eventBuilder = eventBuilder;
    }
    @Override
    public Object getResource() {
        return new PinResource(session, eventBuilder);
    }

    @Override
    public void close() {}

}
