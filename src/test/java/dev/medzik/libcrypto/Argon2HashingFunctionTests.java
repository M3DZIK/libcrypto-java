package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class Argon2HashingFunctionTests {
    @Test
    void hash() {
        Argon2HashingFunction argon2 = new Argon2HashingFunction(32, 1, 65536, 1);

        Argon2Hash hash = argon2.hash("secret password", Salt.generate(16));

        System.out.println(hash);

        assertTrue(Argon2HashingFunction.verify("secret password", hash.toString()));
        // invalid password
        assertFalse(Argon2HashingFunction.verify("invalid password", hash.toString()));
    }

    @Test
    void checkReproducible() {
        String password = "secret password";
        byte[] salt = Salt.generate(16);

        Argon2HashingFunction argon2 = new Argon2HashingFunction(32, 1, 65536, 1);
        Argon2Hash hash = argon2.hash(password, salt);

        Argon2HashingFunction argon2_2 = new Argon2HashingFunction(32, 1, 65536, 1);
        Argon2Hash hash_2 = argon2_2.hash(password, salt);

        assertEquals(hash.toString(), hash_2.toString());
    }

    @Test
    void toHexHash() {
        Argon2HashingFunction argon2 = new Argon2HashingFunction(16, 1, 65536, 1);
        Argon2Hash hash = argon2.hash("secret password", Salt.generate(16));

        String hexHash = hash.toHexHash();

        assertEquals(32, hexHash.length());
    }

    @Test
    void validHash() {
        String hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ";

        assertTrue(Argon2HashingFunction.verify("medzik@duck.com", hash));
    }
}
