package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class Argon2idTests {
    @Test
    void hash() throws IOException {
        Argon2id argon2 = new Argon2id(32, 1, 65536, 1);

        String hash = argon2.hash("secret password", Salt.generate(16));

        assertTrue(Argon2id.verify("secret password", hash));
        // invalid password
        assertFalse(Argon2id.verify("invalid password", hash));
    }

    @Test
    void checkReproducible() {
        String password = "secret password";
        byte[] salt = Salt.generate(16);

        Argon2id argon2 = new Argon2id(32, 1, 65536, 1);
        String hash = argon2.hash(password, salt);

        Argon2id argon2_2 = new Argon2id(32, 1, 65536, 1);
        String hash_2 = argon2_2.hash(password, salt);

        assertEquals(hash, hash_2);
    }

    @Test
    void toHexHash() {
        Argon2id argon2 = new Argon2id(16, 1, 65536, 1);
        String hash = argon2.hash("secret password", Salt.generate(16));

        String hexHash = Argon2id.toHexHash(hash);

        assertEquals(32, hexHash.length());
    }
}
