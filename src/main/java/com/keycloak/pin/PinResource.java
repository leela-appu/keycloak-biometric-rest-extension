package com.keycloak.pin;

import com.keycloak.util.AuthenticationTokenProvider;
import com.keycloak.util.Constants;
import com.keycloak.util.CredentialProviderUtil;
import com.keycloak.util.ResourceUtil;
import com.keycloak.model.request.pin.DeviceRegisterRequest;
import com.keycloak.model.request.pin.PinRegisterRequest;
import com.keycloak.model.request.pin.PinRemoveRequest;
import com.keycloak.model.request.pin.PinValidateRequest;
import com.keycloak.model.response.ResponseData;
import com.keycloak.validate.CustomException;
import com.keycloak.validate.CustomValidator;
import com.keycloak.validate.TokenValidator;
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
import org.keycloak.utils.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PinResource {

    private static final Logger logger = LoggerFactory.getLogger(PinResource.class.getName());
    private final KeycloakSession session;
    private final CustomValidator validator;
    private final TokenValidator tokenValidator;
    private final AuthenticationTokenProvider tokenProvider;
    private final ResourceUtil resourceUtil;
    private final PinCredentialProvider credentialProvider;

    public PinResource(KeycloakSession session, EventBuilder eventBuilder) {
        this.session = session;
        this.validator = new CustomValidator();
        this.tokenValidator = new TokenValidator(session, eventBuilder);
        this.tokenProvider = new AuthenticationTokenProvider(session, eventBuilder);
        this.resourceUtil = new ResourceUtil();
        this.credentialProvider = new PinCredentialProvider(session);
    }

    @GET
    @Path("validate-registration")
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateRegistration(@QueryParam("email") String email, @QueryParam("deviceId") String deviceId) {
        try {
            tokenValidator.validateUserToken(email);
            validator.validateEmail(email);
            validator.validateDeviceId(deviceId);
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found")).build();
            }
            String isRegistered = "{\"isRegistered\": true}";
            PinCredentialModel credentialModel = credentialProvider.getCredentialByDeviceId(existingUser, deviceId);
            if (credentialModel == null || credentialModel.getPinCredentialData().getCredentialPublicKey() == null) {
                isRegistered = "{\"isRegistered\": false}";
            }
            return Response.status(Status.OK).entity(isRegistered).type(MediaType.APPLICATION_JSON).build();
        } catch (NotAuthorizedException | ForbiddenException | VerificationException | CustomException e) {
            return resourceUtil.getErrorResponse(e, true);
        } catch (Exception e) {
            logger.error("Error while validating registration",e);
            String message = "Failed to validate secure pin registration";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message)).build();
        }
    }

    @POST
    @Path("register")
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(@RequestBody PinRegisterRequest request) {
        try {
            String email = request.getEmail();
            tokenValidator.validateUserToken(email);
            validator.validateEmail(email);
            validator.validateDeviceId(request.getDeviceId());
            validator.validatePublicKey(request.getPublicKey());
            validator.validatePin(request.getPin());
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found")).build();
            }
            credentialProvider.createPinCredential(existingUser, request.getPin(), request.getDeviceId(), request.getPublicKey());
            String message = "Pin registered successfully";
            return Response.status(Status.OK).entity(new ResponseData(Status.OK.getStatusCode(), message)).build();
        } catch (NotAuthorizedException | ForbiddenException | VerificationException | CustomException e) {
            return resourceUtil.getErrorResponse(e, true);
        } catch (Exception e) {
            logger.error("Error while register",e);
            String message = "Failed to register pin.";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message)).build();
        }
    }

    @POST
    @Path("register-device")
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerDevice(@RequestBody DeviceRegisterRequest request) {
        try {
            String email = request.getEmail();
            tokenValidator.validateUserToken(email);
            validator.validateEmail(email);
            validator.validateDeviceId(request.getDeviceId());
            validator.validatePublicKey(request.getPublicKey());
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found")).build();
            }
            String securePin = existingUser.getFirstAttribute(Constants.SECURE_PIN);
            if (StringUtil.isBlank(securePin)) {
                String message = "Secure pin not found to register device.";
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), message)).build();
            }
            credentialProvider.addDeviceCredential(existingUser, request.getDeviceId(), request.getPublicKey());
            String message = "Device registered successfully.";
            return Response.status(Status.OK).entity(new ResponseData(Status.OK.getStatusCode(), message)).build();
        } catch (NotAuthorizedException | ForbiddenException | VerificationException | CustomException e) {
            return resourceUtil.getErrorResponse(e, true);
        } catch (Exception e) {
            logger.error("Error while register",e);
            String message = "Failed to save pin.";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message)).build();
        }
    }

    @POST
    @Path("authenticate")
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticate(@RequestBody PinValidateRequest request) {
        try {
            tokenValidator.validateOfflineToken();
            String email = request.getEmail();
            String signature = request.getSignature();
            String deviceId = request.getDeviceId();
            String pin = request.getPin();
            validator.validateEmail(email);
            validator.validatePin(pin);
            validator.validateDeviceId(deviceId);
            validator.validateSignature(signature);
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found")).build();
            }
            PinCredentialModel pinCredentialModel = credentialProvider.getCredentialByDeviceId(existingUser, request.getDeviceId());
            if (pinCredentialModel == null) {
                String message = "User Credential not found for given device id.";
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), message)).build();
            }
            String signatureUniqueKey = existingUser.getFirstAttribute(Constants.PIN_SIGNATURE_KEY+"_"+deviceId);
            if (StringUtil.isBlank(signatureUniqueKey)) {
                String message = "Unique Signature key not found";
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), message)).build();
            }
            if (!CredentialProviderUtil.verifySignature(signatureUniqueKey, signature, pinCredentialModel.getPinCredentialData().getCredentialPublicKey())) {
                return Response.status(Status.FORBIDDEN).entity(new ResponseData(Status.FORBIDDEN.getStatusCode(), "Invalid signature")).build();
            }
            if (StringUtil.isBlank(existingUser.getFirstAttribute(Constants.SECURE_PIN))) {
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), "Secure pin not registered for given user.")).build();
            }
            if (!credentialProvider.verifyPin(existingUser, request.getPin())) {
                return Response.status(Status.FORBIDDEN).entity(new ResponseData(Status.FORBIDDEN.getStatusCode(), "Invalid pin")).build();
            }
            AccessTokenResponse accessTokenResponse = tokenProvider.createAccessToken(existingUser);
            existingUser.removeAttribute(Constants.PIN_SIGNATURE_KEY+"_"+deviceId);
            Cors cors = Cors.add(session.getContext().getHttpRequest()).auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
            return cors.builder(Response.ok(accessTokenResponse).type(MediaType.APPLICATION_JSON_TYPE)).build();
        } catch (NotAuthorizedException | ForbiddenException | CustomException e) {
            return resourceUtil.getErrorResponse(e, true);
        } catch (Exception e) {
            logger.error("Error while authenticate",e);
            String message = "Failed to validate pin.";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message)).build();
        }
    }

    @POST
    @Path("delete")
    @Produces(MediaType.APPLICATION_JSON)
    public Response delete(@RequestBody PinRemoveRequest request) {
        try {
            String email = request.getEmail();
            tokenValidator.validateUserToken(email);
            validator.validateEmail(email);
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found")).build();
            }
            credentialProvider.deletePinCredential(existingUser);
            String message = "Pin deleted successfully";
            return Response.status(Status.OK).entity(new ResponseData(Status.OK.getStatusCode(), message)).build();
        } catch (NotAuthorizedException | ForbiddenException | VerificationException | CustomException e) {
            return resourceUtil.getErrorResponse(e, true);
        } catch (Exception e) {
            logger.error("Error while register",e);
            String message = "Failed to delete pin";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message)).build();
        }
    }

    @GET
    @Path("signature-key")
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateKey(@QueryParam("email") String email, @QueryParam("deviceId") String deviceId) {
        try {
            tokenValidator.validateOfflineToken();
            validator.validateEmail(email);
            validator.validateDeviceId(deviceId);
            UserModel existingUser = resourceUtil.getUserModel(session, email);
            if (existingUser == null) {
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), "User not found")).build();
            }
            PinCredentialModel pinCredentialModel = credentialProvider.getCredentialByDeviceId(existingUser, deviceId);
            if (pinCredentialModel == null) {
                String message = "User Credential not found";
                return Response.status(Status.BAD_REQUEST).entity(new ResponseData(Status.BAD_REQUEST.getStatusCode(), message)).build();
            }
            return Response.status(Status.OK).entity(CredentialProviderUtil.createUniqueSignatureKey(existingUser, deviceId, true)).build();
        }  catch (NotAuthorizedException | ForbiddenException | CustomException e) {
            return resourceUtil.getErrorResponse(e, true);
        } catch (Exception e) {
            logger.error("Error while generateKey", e);
            String message = "Failed to generate unique key";
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity(new ResponseData(Status.INTERNAL_SERVER_ERROR.getStatusCode(), message)).build();
        }
    }
}
