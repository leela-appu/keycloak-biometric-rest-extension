# keycloak-biometric-rest-extension
COPY keycloak-biometric-rest-extension-2.0.0-SNAPSHOT.jar /opt/keycloak/providers

# Why is this plugin required?
This enables biometric authentication per device and a secure PIN per account for the React Native mobile app, allowing device registration and token generation using biometrics and the PIN, respectively.
