package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class Argon2Tests {
    @Test
    void hash() {
        Argon2 argon2 = new Argon2(32, 1, 65536, 1);

        Argon2Hash hash = argon2.hash("secret password", Salt.generate(16));

        assertTrue(Argon2.verify("secret password", hash.toString()));
        // invalid password
        assertFalse(Argon2.verify("invalid password", hash.toString()));
    }

    @Test
    void checkReproducible() {
        String password = "secret password";
        byte[] salt = Salt.generate(16);

        Argon2 argon2 = new Argon2(32, 1, 65536, 1);
        Argon2Hash hash = argon2.hash(password, salt);

        Argon2 argon2_2 = new Argon2(32, 1, 65536, 1);
        Argon2Hash hash_2 = argon2_2.hash(password, salt);

        assertEquals(hash.toString(), hash_2.toString());
    }

    @Test
    void toHexHash() {
        Argon2 argon2 = new Argon2(16, 1, 65536, 1);
        Argon2Hash hash = argon2.hash("secret password", Salt.generate(16));

        String hexHash = hash.toHexHash();

        assertEquals(32, hexHash.length());
    }

    @Test
    void validHash() {
        String hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ";

        assertTrue(Argon2.verify("medzik@duck.com", hash));
    }

    @Test
    void hashUsingBuilder() {
        Argon2 argon2 = new Argon2.Builder()
                .setType(Argon2Type.ID)
                .setHashLength(32)
                .setParallelism(1)
                .setMemory(65536)
                .setIterations(2)
                .setVersion(19)
                .build();

        Argon2Hash hash = argon2.hash("password", "some salt");

        assertEquals(32, hash.getHash().length);
        assertEquals(1, hash.getParallelism());
        assertEquals(65536, hash.getMemory());
        assertEquals(2, hash.getIterations());
    }
}
