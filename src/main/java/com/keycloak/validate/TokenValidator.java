package com.keycloak.validate;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

import static jakarta.ws.rs.core.HttpHeaders.AUTHORIZATION;

public class TokenValidator {
    private static final Logger logger = LoggerFactory.getLogger(TokenValidator.class.getName());
    private final KeycloakSession session;
    private final TokenManager tokenManager;
    private final EventBuilder event;

    public TokenValidator(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.tokenManager = new TokenManager();
        this.event = event;
    }

    public AccessToken validateTokenAndUpdateSession(HttpRequest request) throws Exception {
        try {
            RealmModel realm = session.getContext().getRealm();
            String tokenString = readAccessTokenFrom(request);
            @SuppressWarnings("unchecked") TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class).withChecks(
                    TokenVerifier.IS_ACTIVE,
                    new TokenVerifier.RealmUrlCheck(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()))
            );
            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, verifier.getHeader().getAlgorithm().name()).verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);
            AccessToken accessToken = verifier.verify().getToken();
            if (!tokenManager.checkTokenValidForIntrospection(session, realm, accessToken, true)) {
                throw new VerificationException("introspection_failed");
            }
            return accessToken;
        } catch (VerificationException e) {
            logger.error("Keycloak-ConfigurableToken: introspection of token failed", e);
            throw new Exception("access_token_introspection_failed: "+e.getMessage());
        }
    }

    private String readAccessTokenFrom(HttpRequest request) throws Exception {
        String authorization = request.getHttpHeaders().getHeaderString(AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            logger.warn("Keycloak-ConfigurableToken: no authorization header with bearer token");
            throw new Exception("bearer_token_missing_in_authorization_header");
        }
        String token = authorization.substring(7);
        if (token.isEmpty()) {
            logger.warn("Keycloak-ConfigurableToken: empty access token");
            throw new Exception("missing_access_token");
        }
        return token;
    }

    public void validateUserToken(String givenEmail) throws Exception {
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null || authResult.getToken() == null) {
            throw new NotAuthorizedException("Bearer Token Not Authorized request");
        } else if (authResult.getToken().getIssuedFor() == null || authResult.getToken().getIssuer() == null || isValidateAuthClientId(authResult.getToken().getIssuedFor())) {
            throw new ForbiddenException("Token is not properly issued  for this request");
        } else {
            HttpRequest request = session.getContext().getHttpRequest();
            String tokenString = readAccessTokenFrom(request);
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class).withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), session.getContext().getRealm().getName()));
            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, verifier.getHeader().getAlgorithm().name()).verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);
            AccessToken token = verifier.verify().getToken();
            if (!TokenUtil.hasScope(token.getScope(), OAuth2Constants.SCOPE_OPENID)) {
                throw new VerificationException(OAuthErrorException.INSUFFICIENT_SCOPE);
            }
            ClientModel clientModel = session.getContext().getRealm().getClientByClientId(token.getIssuedFor());
            if (clientModel == null) {
                throw new VerificationException("Client not found");
            }
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(TokenManager.NotBeforeCheck.forModel(clientModel), new TokenManager.TokenRevocationCheck(session))
                    .verify();

            if (!clientModel.getProtocol().equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
                throw new VerificationException("Wrong client protocol");
            }
            session.getContext().setClient(clientModel);
            event.client(clientModel);
            if (!clientModel.isEnabled()) {
                throw new VerificationException("Client disabled");
            }
            UserModel userModel = TokenManager.lookupUserFromStatelessToken(session, session.getContext().getRealm(), token);
            if (userModel == null) {
                throw new VerificationException("User not found");
            }
            if (!userModel.isEnabled()) {
                throw new VerificationException("User disabled");
            }
            if (StringUtil.isBlank(givenEmail) || !givenEmail.equals(userModel.getEmail())) {
                throw new VerificationException("Invalid token for Given email.");
            }
        }
    }

    public void validateOfflineToken() {
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null) {
            throw new NotAuthorizedException("Bearer Token Not Authorized request");
        } else if (authResult.getToken().getIssuedFor() == null || authResult.getToken().getIssuer() == null || isValidateAuthClientId(authResult.getToken().getIssuedFor())) {
            throw new ForbiddenException("Token is not properly issued  for this request");
        }
    }

    private boolean isValidateAuthClientId(String clientId) {
        List<String> clientIdList = Arrays.asList("service-account", "customer_web_app");
        String keycloakAuthClientIds = System.getenv("AUTH_CLIENT_IDS");
        if (StringUtil.isNotBlank(keycloakAuthClientIds)) {
            String[] kcAuthClientIds = keycloakAuthClientIds.split(",");
            List<String> clientIds = Arrays.asList(kcAuthClientIds);
            clientIds.removeIf(str -> str == null || str.trim().isEmpty());
            if (!clientIds.isEmpty()) {
                clientIdList = clientIds;
            }
        }
        return clientIdList.stream().noneMatch(str -> str.equals(clientId));
    }
}
