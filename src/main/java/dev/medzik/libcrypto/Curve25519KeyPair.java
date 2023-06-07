package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;

public class Curve25519KeyPair {
    private final String publicKey;
    private final String privateKey;

    Curve25519KeyPair(byte[] publicKey, byte[] privateKey) {
        this.publicKey = Hex.encodeHexString(publicKey);
        this.privateKey = Hex.encodeHexString(privateKey);
    }

    public String getPublicKey() {
        return this.publicKey;
    }

    public String getPrivateKey() {
        return this.privateKey;
    }
}
