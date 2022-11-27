package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SaltTests {
    int length =  16;

    @Test
    void getSalt() {
        byte[] salt = new Salt().generate(length);

        assertEquals(salt.length, length);
    }
}
