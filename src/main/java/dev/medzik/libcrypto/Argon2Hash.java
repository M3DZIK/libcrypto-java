package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;

/**
 * Represents an Argon2 hash with its parameters.
 */
public class Argon2Hash {
    private final Argon2Type type;
    private final int version;
    private final int memory;
    private final int iterations;
    private final int parallelism;

    private final byte[] salt;
    private final byte[] hash;

    public Argon2Hash(Argon2Type type, int version, int memory, int iterations, int parallelism, byte[] salt, byte[] hash) {
        this.type = type;
        this.version = version;
        this.memory = memory;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.salt = salt;
        this.hash = hash;
    }

    /**
     * Returns the Argon2 type of this hash.
     */
    public Argon2Type getType() {
        return type;
    }

    /**
     * Returns version of this hash.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Returns memory parameter of this hash.
     */
    public int getMemory() {
        return memory;
    }

    /**
     * Returns iterations parameter of this hash.
     */
    public int getIterations() {
        return iterations;
    }

    /**
     * Returns parallelism parameter of this hash.
     */
    public int getParallelism() {
        return parallelism;
    }

    /**
     * Returns salt of this hash.
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Returns hash.
     */
    public byte[] getHash() {
        return hash;
    }

    /**
     * Returns the hash length.
     */
    public int getHashLength() {
        return hash.length;
    }

    /**
     * Returns the hash encoded in hex.
     */
    public String toHexHash() {
        return Hex.encodeHexString(hash);
    }

    /**
     * Same as {@link #toArgon2String()}.
     */
    @Override
    public String toString() {
        return toArgon2String();
    }

    /**
     * Returns hash in argon2 format. Example: $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$Zm9vYmFy
     */
    public String toArgon2String() {
        return Argon2EncodingUtils.encode(this);
    }
}
