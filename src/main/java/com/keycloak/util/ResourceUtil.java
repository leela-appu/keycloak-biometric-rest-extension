package com.keycloak.util;

import com.keycloak.model.response.ResponseData;
import com.keycloak.validate.CustomException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ResourceUtil {

    private static final Logger logger = LoggerFactory.getLogger(ResourceUtil.class.getName());

    public UserModel getUserModel(KeycloakSession session, String email) {
        RealmModel realm = session.getContext().getRealm();
        // Retrieve user from Keycloak by user id
        return session.users().getUserByEmail(realm, email);
    }

    public Response getErrorResponse(Exception e, boolean isV2) {
        Response.Status  status = Response.Status.UNAUTHORIZED;
        if (e instanceof ForbiddenException) {
            status = Response.Status.FORBIDDEN;
        } else if (e instanceof CustomException) {
            status = Response.Status.BAD_REQUEST;
        }
        logger.error(status.getReasonPhrase(), e);
        return Response.status(status).entity(isV2 ? new ResponseData(status.getStatusCode(), e.getMessage()) : e.getMessage()).build();
    }
}
