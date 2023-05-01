package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AesCbcTests {
    @Test
    void encrypt_decrypt() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String input = "Hello World!";
        String cipherText =  AesCbc.encrypt(input, secretKey);
        String clearText = AesCbc.decrypt(cipherText, secretKey);

        assertEquals(input, clearText);
    }

    @Test
    void decrypt() throws EncryptException {
        String secretKey = new Pbkdf2(1000).sha256("secret passphrase", "salt".getBytes());

        String cipherText = "ae77d812f4494a766a94b5dff8e7aa3c8408544b9fd30cd13b886cc5dd1b190e";
        String clearText = AesCbc.decrypt(cipherText, secretKey);

        assertEquals("hello world", clearText);
    }

    @Test
    void argon2Encrypt() throws EncryptException {
        Argon2id argon2 = new Argon2id(256 / 8, 1, 65536, 1);
        String hash = argon2.hash("secret password", Salt.generate(16));
        String secretKey = Argon2id.toHexHash(hash);

        String input = "Hello World!";
        String cipherText =  AesCbc.encrypt(input, secretKey);
        String clearText = AesCbc.decrypt(cipherText, secretKey);

        assertEquals(input, clearText);
    }
}
