package dev.medzik.libcrypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import java.security.InvalidParameterException;

/**
 * Curve25519 implementation.
 */
public class Curve25519 {
    /**
     * Generate a new X25519 key pair.
     * @return X25519 key pair.
     */
    public static Curve25519KeyPair generateKeyPair() {
        byte[] privateKey = com.github.netricecake.ecdh.Curve25519.generateRandomKey();
        byte[] publicKey = com.github.netricecake.ecdh.Curve25519.publicKey(privateKey);

        return new Curve25519KeyPair(publicKey, privateKey);
    }

    /**
     * Return a X25519 key pair from a private key.
     * @param privateKey private key to recover (hex encoded)
     * @return X25519 key pair.
     */
    public static Curve25519KeyPair fromPrivateKey(String privateKey) throws DecoderException, InvalidParameterException {
        byte[] privateKeyBytes = Hex.decodeHex(privateKey);
        byte[] publicKeyBytes = com.github.netricecake.ecdh.Curve25519.publicKey(privateKeyBytes);

        return new Curve25519KeyPair(publicKeyBytes, privateKeyBytes);
    }

    /**
     * Compute a shared secret given our private key and their public key.
     * @param ourPrivate our private key
     * @param theirPublic their public key
     * @return Shared secret.
     */
    public static String computeSharedSecret(String ourPrivate, String theirPublic) throws DecoderException {
        byte[] outPrivateBytes = Hex.decodeHex(ourPrivate);
        byte[] theirPublicBytes = Hex.decodeHex(theirPublic);

        byte[] sharedSecret = com.github.netricecake.ecdh.Curve25519.sharedSecret(outPrivateBytes, theirPublicBytes);

        return Hex.encodeHexString(sharedSecret);
    }
}
