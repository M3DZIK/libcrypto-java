package dev.medzik.libcrypto;

import java.security.SecureRandom;

public class Salt {
    /**
     * Generate a random salt slice.
     * @param length The length of the salt slice.
     * @return Salt slice in byte[].
     */
    public static byte[] generate(int length) {
        SecureRandom rd = new SecureRandom();
        byte[] salt = new byte[length];
        rd.nextBytes(salt);
        return salt;
    }
}
