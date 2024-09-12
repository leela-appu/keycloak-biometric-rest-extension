package com.keycloak.biometric;

import com.keycloak.model.request.biometric.PublicKeyRegisterRequest;
import com.keycloak.model.request.biometric.PublicKeyRemoveRequest;
import com.keycloak.model.request.biometric.SignatureValidateRequest;
import com.keycloak.model.response.ResponseData;
import com.keycloak.util.AuthenticationTokenProvider;
import com.keycloak.util.Constants;
import com.keycloak.util.CredentialProviderUtil;
import com.keycloak.util.ResourceUtil;
import com.keycloak.validate.CustomException;
import com.keycloak.validate.CustomValidator;
import com.keycloak.validate.TokenValidator;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.keycloak.common.VerificationException;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.resources.Cors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BiometricResource {


    private static final Logger logger = LoggerFactory.getLogger(BiometricResource.class.getName());
    private final KeycloakSession session;
    private final CustomValidator validator;
    private final TokenValidator tokenValidator;
    private final AuthenticationTokenProvider tokenProvider;
    private final ResourceUtil resourceUtil;
    private final BiometricCredentialProvider credentialProvider;

    public BiometricResource(KeycloakSession session, EventBuilder eventBuilder) {
        this.session = session;
        this.validator = new CustomValidator();
        this.tokenValidator = new TokenValidator(session, eventBuilder);
        this.tokenProvider = new AuthenticationTokenProvider(session, eventBuilder);
        this.resourceUtil = new ResourceUtil();
        this.credentialProvider = new BiometricCredentialProvider(session);
    }

    @GET
    @Path("validate-registration")
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateRegistration(@QueryParam("email") String email, @QueryParam("deviceId") String deviceId) {
        return validateRegistration(email, deviceId, false);
    }

    @GET
    @Path("v2/validate-registration")
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateRegistrationV2(@QueryParam("email") String email, @QueryParam("deviceId") String deviceId) {
        return validateRegistration(email, deviceId, true);
    }

    private Response validateRegistration(String email, String deviceId, boolean isV2) {
        try {
            tokenValidator.validateUserToken(email);
            validator.validateEmail(email);
            validator.validateDeviceId(deviceId);
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found") : "User not found").build();
            }
            String isRegistered = "{\"isRegistered\": true}";
            BiometricCredentialModel credentialModel = credentialProvider.getCredentialByDeviceId(existingUser, deviceId);
            if (credentialModel == null || credentialModel.getBiometricCredentialData().getCredentialPublicKey() == null) {
                isRegistered = "{\"isRegistered\": false}";
            }
            return Response.status(Status.OK).entity(isRegistered).type(MediaType.APPLICATION_JSON).build();
        } catch (NotAuthorizedException | ForbiddenException | VerificationException | CustomException e) {
            return resourceUtil.getErrorResponse(e, isV2);
        } catch (Exception e) {
            logger.error("Error while validating registration",e);
            String message = "Failed to validate public key registered or not for given device id";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(isV2 ? new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message) : message).build();
        }
    }

    @POST
    @Path("register")
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(@RequestBody PublicKeyRegisterRequest request) {
        return register(request, false);
    }

    @POST
    @Path("v2/register")
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerV2(@RequestBody PublicKeyRegisterRequest request) {
        return register(request, true);
    }

    private Response register(PublicKeyRegisterRequest request, boolean isV2) {
        try {
            String email = request.getEmail();
            tokenValidator.validateUserToken(email);
            validator.validateEmail(email);
            validator.validateDeviceId(request.getDeviceId());
            validator.validatePublicKey(request.getPublicKey());
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found") : "User not found").build();
            }
            credentialProvider.createBiometricCredential(existingUser, request.getDeviceId(), request.getPublicKey());
            String message = "Biometric public key saved successfully";
            return Response.status(Status.OK).entity(isV2 ? new ResponseData(Status.OK.getStatusCode(), message) : message).build();
        } catch (NotAuthorizedException | ForbiddenException | VerificationException | CustomException e) {
            return resourceUtil.getErrorResponse(e, isV2);
        } catch (Exception e) {
            logger.error("Error while register",e);
            String message = "Failed to save biometric public key";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(isV2 ? new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message) : message).build();
        }
    }

    @POST
    @Path("authenticate")
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticate(@RequestBody SignatureValidateRequest request) {
        return authenticate(request, false);
    }

    @POST
    @Path("v2/authenticate")
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticateV2(@RequestBody SignatureValidateRequest request) {
        return authenticate(request, true);
    }

    private Response authenticate(SignatureValidateRequest request, boolean isV2) {
        try {
            tokenValidator.validateOfflineToken();
            String email = request.getEmail();
            String signature = request.getSignature();
            String deviceId = request.getDeviceId();
            validator.validateEmail(email);
            validator.validateSignature(signature);
            validator.validateDeviceId(deviceId);
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found") : "User not found").build();
            }
            BiometricCredentialModel biometricCredentialModel = credentialProvider.getCredentialByDeviceId(existingUser, request.getDeviceId());
            if (biometricCredentialModel == null) {
                String message = "User Credential not found";
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), message) : message).build();
            }
            String signatureUniqueKey = existingUser.getFirstAttribute(Constants.BIO_SIGNATURE_KEY+"_"+deviceId);
            if (signatureUniqueKey == null) {
                String message = "Signature unique key not found";
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), message) : message).build();
            }
            if (!CredentialProviderUtil.verifySignature(signatureUniqueKey, signature, biometricCredentialModel.getBiometricCredentialData().getCredentialPublicKey())) {
                return Response.status(Status.FORBIDDEN).entity(isV2 ? new ResponseData(Status.FORBIDDEN.getStatusCode(), "Invalid signature") : "Invalid signature").build();
            }
            AccessTokenResponse accessTokenResponse = tokenProvider.createAccessToken(existingUser);
            existingUser.removeAttribute(Constants.BIO_SIGNATURE_KEY+"_"+deviceId);
            Cors cors = Cors.add(session.getContext().getHttpRequest()).auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
            return cors.builder(Response.ok(accessTokenResponse).type(MediaType.APPLICATION_JSON_TYPE)).build();
        } catch (NotAuthorizedException | ForbiddenException | CustomException e) {
            return resourceUtil.getErrorResponse(e, isV2);
        } catch (Exception e) {
            logger.error("Error while authenticate",e);
            String message = "Failed to validate biometric public key";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(isV2 ? new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message) : message).build();
        }
    }

    @GET
    @Path("signature-key")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateKey(@QueryParam("email") String email, @QueryParam("deviceId") String deviceId) {
        return generateKey(email, deviceId, false);
    }

    @GET
    @Path("v2/signature-key")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateKeyV2(@QueryParam("email") String email, @QueryParam("deviceId") String deviceId) {
        return generateKey(email, deviceId, true);
    }

    private Response generateKey(String email, String deviceId, boolean isV2) {
        tokenValidator.validateOfflineToken();
        try {
            validator.validateEmail(email);
            validator.validateDeviceId(deviceId);
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found") : "User not found").build();
            }
            BiometricCredentialModel biometricCredentialModel = credentialProvider.getCredentialByDeviceId(existingUser, deviceId);
            if (biometricCredentialModel == null) {
                String message = "User Credential not found";
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), message) : message).build();
            }
            return Response.status(Response.Status.OK).entity(CredentialProviderUtil.createUniqueSignatureKey(existingUser, deviceId, false)).build();
        }  catch (NotAuthorizedException | ForbiddenException | CustomException e) {
            return resourceUtil.getErrorResponse(e, isV2);
        } catch (Exception e) {
            logger.error("Error while generateKey", e);
            String message = "Failed to generate unique key";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(isV2 ? new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message) : message).build();
        }
    }

    @POST
    @Path("delete")
    @Produces(MediaType.APPLICATION_JSON)
    public Response delete(@Valid PublicKeyRemoveRequest request) {
        return delete(request, false);
    }

    @POST
    @Path("v2/delete")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteV2(@Valid PublicKeyRemoveRequest request) {
        return delete(request, true);
    }

    private Response delete(PublicKeyRemoveRequest request, boolean isV2) {
        try {
            String email = request.getEmail();
            tokenValidator.validateUserToken(email);
            validator.validateEmail(email);
            validator.validateDeviceId(request.getDeviceId());
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found") : "User not found").build();
            }
            if (credentialProvider.deleteBiometricCredential(existingUser, request.getDeviceId())) {
                String message = "Biometric public key deleted successfully";
                return Response.status(Response.Status.OK).entity(isV2 ? new ResponseData(Status.OK.getStatusCode(), message) : message).build();
            } else {
                String message = "Not found Biometric public key to delete";
                return Response.status(Response.Status.BAD_REQUEST).entity(isV2 ? new ResponseData(Status.BAD_REQUEST.getStatusCode(), message) : message).build();
            }
        } catch (NotAuthorizedException | ForbiddenException | VerificationException | CustomException e) {
            return resourceUtil.getErrorResponse(e, isV2);
        } catch (Exception e) {
            logger.error("Error while register",e);
            String message = "Failed to delete biometric public key";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(isV2 ? new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message) : message).build();
        }
    }
}
