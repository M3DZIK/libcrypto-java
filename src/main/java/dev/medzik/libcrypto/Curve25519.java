package dev.medzik.libcrypto;

import com.google.crypto.tink.subtle.X25519;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import java.security.InvalidKeyException;

/**
 * Curve25519 implementation using Google Tink.
 */
public class Curve25519 {
    /**
     * Generate a new X25519 key pair.
     * @return X25519 key pair.
     */
    public static Curve25519KeyPair generateKeyPair() throws InvalidKeyException, DecoderException {
        byte[] privateKey = X25519.generatePrivateKey();
        return fromPrivateKey(Hex.encodeHexString(privateKey));
    }

    /**
     * Return a X25519 key pair from a private key.
     * @param privateKey private key to recover (hex encoded)
     * @return X25519 key pair.
     */
    public static Curve25519KeyPair fromPrivateKey(String privateKey) throws DecoderException, InvalidKeyException {
        byte[] privateKeyBytes = Hex.decodeHex(privateKey);
        byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);

        return new Curve25519KeyPair(publicKeyBytes, publicKeyBytes);
    }

    /**
     * Compute a shared secret given our private key and their public key.
     * @param ourPrivate our private key
     * @param theirPublic their public key
     * @return Shared secret.
     */
    public static String computeSharedSecret(String ourPrivate, String theirPublic) throws DecoderException, InvalidKeyException {
        byte[] outPrivateBytes = Hex.decodeHex(ourPrivate);
        byte[] theirPublicBytes = Hex.decodeHex(theirPublic);

        byte[] sharedSecret = X25519.computeSharedSecret(outPrivateBytes, theirPublicBytes);

        return Hex.encodeHexString(sharedSecret);
    }
}
