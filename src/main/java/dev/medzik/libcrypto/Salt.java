package dev.medzik.libcrypto;

import java.security.SecureRandom;

public class Salt {
    /**
     * Generate a random salt slice.
     * @param length length of salt slice in bytes
     * @return Salt slice.
     */
    public static byte[] generate(int length) {
        SecureRandom rd = new SecureRandom();
        byte[] salt = new byte[length];
        rd.nextBytes(salt);
        return salt;
    }
}
