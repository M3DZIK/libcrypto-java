package dev.medzik.libcrypto;

/**
 * Argon2 type.
 */
public enum Argon2Type {
    /**
     * Argon2d type.
     */
    D,
    /**
     * Argon2i type.
     */
    I,
    /**
     * Argon2id type.
     */
    ID;

    /**
     * Get Argon2 type from ordinal.
     * @param ordinal ordinal
     * @return Argon2 type
     */
    public static Argon2Type fromOrdinal(int ordinal) {
        return values()[ordinal];
    }
}
