package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AESTests {
    @Test
    void encryptAndDecryptUsingCBC() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String input = "Hello World!";
        String cipherText =  AES.encrypt(AES.CBC, secretKey, input);
        String clearText = AES.decrypt(AES.CBC, secretKey, cipherText);

        assertEquals(input, clearText);
    }

    @Test
    void decryptUsingCBC() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String cipherText = "ae77d812f4494a766a94b5dff8e7aa3c8408544b9fd30cd13b886cc5dd1b190e";
        String clearText = AES.decrypt(AES.CBC, secretKey, cipherText);

        assertEquals("hello world", clearText);
    }

    @Test
    void encryptAndDecryptUsingGCM() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String input = "Hello World!";
        String cipherText =  AES.encrypt(AES.GCM, secretKey, input);
        String clearText = AES.decrypt(AES.GCM, secretKey, cipherText);

        assertEquals(input, clearText);
    }

    @Test
    void decryptGCM() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String cipherText = "0996c65a72a60e748415dc6d32da1d4dcb65f41c71d4bec9554424218839b5d4b9d9195e5eea9d";
        String clearText = AES.decrypt(AES.GCM, secretKey, cipherText);

        assertEquals("hello world", clearText);
    }
}
