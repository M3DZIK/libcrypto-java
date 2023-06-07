package dev.medzik.libcrypto;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

public class Curve25519Tests {
    @Test
    public void testGenerateKeyPair() {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        assert keyPair.getPrivateKey().length() == 64;
        assert keyPair.getPublicKey().length() == 64;
    }

    @Test
    public void testCalculateAgreement() throws DecoderException {
        Curve25519KeyPair our = Curve25519.generateKeyPair();
        Curve25519KeyPair their = Curve25519.generateKeyPair();

        String ourPrivate = our.getPrivateKey();
        String theirPublic = their.getPublicKey();

        String sharedSecret = Curve25519.calculateAgreement(ourPrivate, theirPublic);

        assert sharedSecret.length() == 64;
    }

    @Test
    public void testCalculateAgreementEncrypt() throws DecoderException, EncryptException {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        String ourPrivate = keyPair.getPrivateKey();
        String theirPublic = keyPair.getPublicKey();

        String sharedSecret = Curve25519.calculateAgreement(ourPrivate, theirPublic);

        String cipherText = AesCbc.encrypt("Hello, world!", sharedSecret);

        String theirPrivate = keyPair.getPrivateKey();
        String outPublic = keyPair.getPublicKey();

        String sharedSecretTwo = Curve25519.calculateAgreement(theirPrivate, outPublic);

        String plainText = AesCbc.decrypt(cipherText, sharedSecretTwo);

        assert plainText.equals("Hello, world!");
    }

    @Test
    public void testCalculateSignature() throws DecoderException {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        String privateKey = keyPair.getPrivateKey();
        byte[] message = "Hello, world!".getBytes();

        String signature = Curve25519.calculateSignature(privateKey, message);

        assert signature.length() == 128;
    }

    @Test
    public void testVerifySignature() throws DecoderException {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        String publicKey = keyPair.getPublicKey();
        byte[] message = "Hello, world!".getBytes();
        String signature = Curve25519.calculateSignature(keyPair.getPrivateKey(), message);

        assert Curve25519.verifySignature(publicKey, message, signature);
    }

    @Test
    public void testVerifySignatureInvalidSignature() throws DecoderException {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        String publicKey = keyPair.getPublicKey();
        byte[] message = "Hello, world!".getBytes();
        String signature = Curve25519.calculateSignature(keyPair.getPrivateKey(), message);

        signature = signature.substring(1, signature.length() - 1);

        assert !Curve25519.verifySignature(publicKey, message, signature);
    }

    @Test
    public void testVerifySignatureInvalidMessage() throws DecoderException {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        String publicKey = keyPair.getPublicKey();
        byte[] message = "Hello, world!".getBytes();
        String signature = Curve25519.calculateSignature(keyPair.getPrivateKey(), message);

        assert !Curve25519.verifySignature(publicKey, "Goodbye, world!".getBytes(), signature);
    }
}
