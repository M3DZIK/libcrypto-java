package dev.medzik.libcrypto;

import java.util.Random;

public class Salt {
    /**
     * Generate a random salt slice.
     * @param length The length of the salt slice.
     * @return Salt slice in byte[].
     */
    public byte[] generate(int length) {
        Random rd = new Random();
        byte[] salt = new byte[length];
        rd.nextBytes(salt);
        return salt;
    }
}
