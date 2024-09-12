package com.keycloak.validate;

import org.keycloak.utils.StringUtil;

import java.util.regex.Pattern;

public class CustomValidator {
    private final Pattern pattern;

    public CustomValidator() {
        this.pattern = Pattern.compile("\\d{4}");
    }

    public void validateEmail(String email) throws CustomException {
        if (StringUtil.isBlank(email)) {
           throw new CustomException(ErrorCode.EMPTY_EMAIL.getMessage());
        }
    }

    public void validateDeviceId(String deviceId) throws CustomException {
        if (StringUtil.isBlank(deviceId)) {
            throw new CustomException(ErrorCode.EMPTY_DEVICE_ID.getMessage());
        }
    }

    public void validatePublicKey(String publicKey) throws CustomException {
        if (StringUtil.isBlank(publicKey)) {
            throw new CustomException(ErrorCode.EMPTY_PUBLIC_KEY.getMessage());
        }
    }

    public void validateSignature(String signature) throws CustomException {
        if (StringUtil.isBlank(signature)) {
            throw new CustomException(ErrorCode.EMPTY_SIGNATURE.getMessage());
        }
    }

    public void validatePin(String pin) throws CustomException {
        if (StringUtil.isBlank(pin)) {
            throw new CustomException(ErrorCode.EMPTY_PIN.getMessage());
        }
        if (!pattern.matcher(pin).matches()) {
            throw new CustomException(ErrorCode.INVALID_PIN.getMessage());
        }
    }
}
