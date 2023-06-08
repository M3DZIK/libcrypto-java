package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AesGcmTests {
    @Test
    void encrypt_decrypt() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String input = "Hello World!";
        String cipherText =  AesGcm.encrypt(secretKey, input);
        String clearText = AesGcm.decrypt(secretKey, cipherText);

        System.out.println(cipherText);

        assertEquals(input, clearText);
    }

    @Test
    void decrypt() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String cipherText = "0996c65a72a60e748415dc6d32da1d4dcb65f41c71d4bec9554424218839b5d4b9d9195e5eea9d";
        String clearText = AesGcm.decrypt(secretKey, cipherText);

        assertEquals("hello world", clearText);
    }

    @Test
    void argon2Encrypt() throws EncryptException {
        Argon2 argon2 = new Argon2(256 / 8, 1, 65536, 1);
        Argon2Hash hash = argon2.hash("secret password", Salt.generate(16));
        String secretKey = hash.toHexHash();

        String input = "Hello World!";
        String cipherText =  AesGcm.encrypt(secretKey, input);
        String clearText = AesGcm.decrypt(secretKey, cipherText);

        assertEquals(input, clearText);
    }
}
