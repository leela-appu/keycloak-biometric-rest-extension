package com.keycloak.util;

import com.keycloak.model.response.biometric.SignatureKeyResponse;
import org.keycloak.models.UserModel;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CredentialProviderUtil {

    public static String generateUniqueSignatureKey(String email) throws NoSuchAlgorithmException {
        // Create a secure random number generator
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        // Generate a random value
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        // Combine the email and random value
        String combinedString = email + ":" + bytesToHex(randomBytes);
        // Compute a hash (SHA-256) of the combined string
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(combinedString.getBytes());
        // Convert the hash bytes to hexadecimal string
        return bytesToHex(hashBytes);
    }

    // Helper method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Method to verify the signature
    public static boolean verifySignature(String data, String signature, String publicKeyString) throws Exception {
        PublicKey publicKey = decodeStringToPublicKey(publicKeyString);
        // Initialize Signature object with the public key
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        // Update the Signature object with the data
        verifier.update(data.getBytes());
        // Decode the base64-encoded signature string
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        // Verify the signature
        return verifier.verify(signatureBytes);
    }

    // Method to parse the RSA public key string into a PublicKey object
    public static PublicKey parsePublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        return decodeStringToPublicKey(publicKeyPEM);
    }

    // Method to encode a public key to a string
    public static String encodePublicKeyToString(PublicKey publicKey) {
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }

    // Method to decode a string to a public key
    private static PublicKey decodeStringToPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Or any other algorithm
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    public static String pinEncryptOrDecrypt(String value, boolean isEncrypt) throws Exception {
        String key = System.getenv("PIN_ENCRYPT_KEY");
        String initVector = System.getenv("PIN_ENCRYPT_IV");
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKeySpec = new SecretKeySpec(hexStringToByteArray(key), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        if (isEncrypt) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(value));
            return new String(original);
        }
    }

    private static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }

    public static SignatureKeyResponse createUniqueSignatureKey(UserModel userModel, String deviceId, boolean isSecurePin) throws NoSuchAlgorithmException {
        String signatureKey = Constants.BIO_SIGNATURE_KEY+"_"+deviceId;
        if (isSecurePin) {
            signatureKey = Constants.PIN_SIGNATURE_KEY+"_"+deviceId;
        }
        userModel.removeAttribute(signatureKey);
        String signatureUniqueKey = generateUniqueSignatureKey(userModel.getEmail());
        // Store signature unique key in user attributes
        userModel.setSingleAttribute(signatureKey, signatureUniqueKey);
        return new SignatureKeyResponse(userModel.getEmail(), signatureUniqueKey);
    }

}
