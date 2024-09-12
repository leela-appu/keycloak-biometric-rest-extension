package com.keycloak.util;

import com.keycloak.validate.TokenValidator;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.utils.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticationTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationTokenProvider.class.getName());
    private final KeycloakSession session;
    private final EventBuilder event;
    private final TokenManager tokenManager;
    private final TokenValidator tokenValidator;

    public AuthenticationTokenProvider(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.event = event;
        this.tokenManager = new TokenManager();
        this.tokenValidator = new TokenValidator(session, event);
    }

    public AccessTokenResponse createAccessToken(UserModel existingUser) throws Exception {
        HttpRequest request = session.getContext().getHttpRequest();
        RealmModel realm = this.session.getContext().getRealm();
        AccessToken accessToken = tokenValidator.validateTokenAndUpdateSession(request);
        UserSessionModel userSession = session.sessions().createUserSession(null, realm, existingUser, existingUser.getUsername(), session.getContext().getConnection().getRemoteAddr(), "impersonate", false, null, null, UserSessionModel.SessionPersistenceState.PERSISTENT);
        String keycloakUserClientId = System.getenv("USER_AUTH_CLIENT_ID");
        if (StringUtil.isNullOrEmpty(keycloakUserClientId)) {
            keycloakUserClientId = "customer_web_app";
        }
        ClientModel client = realm.getClientByClientId(keycloakUserClientId);
        session.getContext().setClient(client);
        logger.info("Configurable token requested for username: {}, client: {}, realm: {}", userSession.getUser().getUsername(), client.getClientId(), realm.getName());

        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().getRootAuthenticationSession(realm, userSession.getId());
        if (rootAuthSession == null) {
            if (userSession.getUser().getServiceAccountClientLink() == null) {
                rootAuthSession = session.authenticationSessions().createRootAuthenticationSession(realm, userSession.getId());
            } else {
                // if the user session is associated with a service account
                rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
            }
        }
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(userSession.getUser());
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        AuthenticationManager.setClientScopesInSession(authSession);
        ClientSessionContext clientSessionContext = TokenManager.attachAuthenticationSession(session, userSession, authSession);
        clientSessionContext.setAttribute("iss", accessToken.getIssuer());
        AccessToken newToken = tokenManager.createClientAccessToken(session, realm, client, userSession.getUser(), userSession, clientSessionContext);
        AccessToken newOIDCAccessToken = tokenManager.transformAccessToken(session, newToken, userSession, clientSessionContext);

        return buildResponse(realm, userSession, client, clientSessionContext, newOIDCAccessToken.issuer(accessToken.getIssuer()));
    }

    private AccessTokenResponse buildResponse(RealmModel realm,
                                              UserSessionModel userSession,
                                              ClientModel client,
                                              ClientSessionContext clientSessionContext,
                                              AccessToken token) {
        event.success();
        return tokenManager.responseBuilder(realm, client, event, session, userSession, clientSessionContext)
                .accessToken(token).generateRefreshToken()
                .build();
    }
}
