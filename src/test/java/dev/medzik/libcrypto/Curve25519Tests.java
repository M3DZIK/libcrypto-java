package dev.medzik.libcrypto;

import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Curve25519Tests {
    @Test
    public void testGenerateKeyPair() {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        assert keyPair.getPrivateKey().length() == 64;
        assert keyPair.getPublicKey().length() == 64;
    }

    @Test
    public void textComputeSharedSecret() throws DecoderException {
        Curve25519KeyPair our = Curve25519.generateKeyPair();
        Curve25519KeyPair their = Curve25519.generateKeyPair();

        String ourPrivate = our.getPrivateKey();
        String theirPublic = their.getPublicKey();

        String sharedSecret = Curve25519.computeSharedSecret(ourPrivate, theirPublic);

        assert sharedSecret.length() == 64;
    }

    @Test
    public void textComputeSharedSecret2() throws DecoderException {
        String privateKey = "3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48";
        String publicKey = "9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25";

        String sharedSecret = Curve25519.computeSharedSecret(privateKey, publicKey);

        assert sharedSecret.equals("2bebf3c397ab3c79db9aeeb2c1523ab4a32bd1ae335a19cd47e35983a5184d09");
    }

    @Test
    public void testKeyPairFromPrivate() throws DecoderException {
        String privateKey = "3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48";
        String publicKey = "9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25";

        Curve25519KeyPair keyPair = Curve25519.fromPrivateKey(privateKey);

        assertEquals(privateKey, keyPair.getPrivateKey());
        assertEquals(publicKey, keyPair.getPublicKey());
    }

    @Test
    public void testCalculateAgreementEncrypt() throws DecoderException, EncryptException {
        Curve25519KeyPair keyPair = Curve25519.generateKeyPair();

        String ourPrivate = keyPair.getPrivateKey();
        String theirPublic = keyPair.getPublicKey();

        String sharedSecret = Curve25519.computeSharedSecret(ourPrivate, theirPublic);

        String cipherText = AES.encrypt(AES.GCM, sharedSecret, "Hello, world!");

        String theirPrivate = keyPair.getPrivateKey();
        String outPublic = keyPair.getPublicKey();

        String sharedSecretTwo = Curve25519.computeSharedSecret(theirPrivate, outPublic);

        String plainText = AES.decrypt(AES.GCM, sharedSecretTwo, cipherText);

        assert plainText.equals("Hello, world!");
    }
}
