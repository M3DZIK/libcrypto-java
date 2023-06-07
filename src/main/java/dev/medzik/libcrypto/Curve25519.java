package dev.medzik.libcrypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * Curve25519 implementation. This class is a wrapper around the WhisperSystems Curve25519 implementation
 * with a Hex encoding/decoding layer.
 * <a href="https://en.wikipedia.org/wiki/Curve25519">See Curve25519 on Wikipedia</a>
 */
public class Curve25519 {
    private static final org.whispersystems.curve25519.Curve25519 curve25519 = org.whispersystems.curve25519.Curve25519.getInstance(org.whispersystems.curve25519.Curve25519.JAVA);

    /**
     * Generate a new Curve25519 key pair.
     * @return Curve25519 key pair.
     */
    public static Curve25519KeyPair generateKeyPair() {
        org.whispersystems.curve25519.Curve25519KeyPair keyPair = curve25519.generateKeyPair();
        return new Curve25519KeyPair(keyPair.getPublicKey(), keyPair.getPrivateKey());
    }

    /**
     * Calculate a shared secret given our private key and their public key.
     * @param ourPrivate our private key
     * @param theirPublic their public key
     * @return Shared secret.
     */
    public static String calculateAgreement(String ourPrivate, String theirPublic) throws DecoderException {
        byte[] outPrivateBytes = Hex.decodeHex(ourPrivate);
        byte[] theirPublicBytes = Hex.decodeHex(theirPublic);

        byte[] sharedSecret = curve25519.calculateAgreement(outPrivateBytes, theirPublicBytes);

        return Hex.encodeHexString(sharedSecret);
    }

    /**
     * Calculate a Curve25519 signature given a private key and a message.
     * @param privateKey private key to signing
     * @param message message to sign (hex encoded)
     * @return Curve25519 signature.
     */
    public static String calculateSignature(String privateKey, String message) throws DecoderException {
        byte[] privateKeyBytes = Hex.decodeHex(privateKey);
        byte[] messageBytes = Hex.decodeHex(message);

        byte[] signature = curve25519.calculateSignature(privateKeyBytes, messageBytes);

        return Hex.encodeHexString(signature);
    }

    /**
     * Calculate a Curve25519 signature given a private key and a message.
     * @param privateKey private key to signing
     * @param message message to sign
     * @return Curve25519 signature.
     */
    public static String calculateSignature(String privateKey, byte[] message) throws DecoderException {
        return calculateSignature(privateKey, Hex.encodeHexString(message));
    }

    /**
     * Verify a Curve25519 signature given a public key, message, and signature.
     * @param publicKey public key to verify
     * @param message message to verify (hex encoded)
     * @param signature signature to verify
     * @return True if the signature is valid, false otherwise.
     */
    public static boolean verifySignature(String publicKey, String message, String signature) throws DecoderException {
        byte[] publicKeyBytes = Hex.decodeHex(publicKey);
        byte[] messageBytes = Hex.decodeHex(message);
        byte[] signatureBytes = Hex.decodeHex(signature);

        return curve25519.verifySignature(publicKeyBytes, messageBytes, signatureBytes);
    }

    /**
     * Verify a Curve25519 signature given a public key, message, and signature.
     * @param publicKey public key to verify
     * @param message message to verify
     * @param signature signature to verify
     * @return True if the signature is valid, false otherwise.
     */
    public static boolean verifySignature(String publicKey, byte[] message, String signature) throws DecoderException {
        return verifySignature(publicKey, Hex.encodeHexString(message), signature);
    }
}
