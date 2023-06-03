package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;

/**
 * Represents an Argon2 hash with its parameters.
 */
public class Argon2Hash {
    /**
     * The Argon2 type of this hash. (Argon2d, Argon2i, Argon2id)
     */
    private final Argon2Type type;
    /**
     * The version of this hash.
     */
    private final int version;
    /**
     * The memory parameter of this hash.
     */
    private final int memory;
    /**
     * The iterations parameter of this hash.
     */
    private final int iterations;
    /**
     * The parallelism parameter of this hash.
     */
    private final int parallelism;
    /**
     * The salt of this hash.
     */
    private final byte[] salt;
    /**
     * The hash.
     */
    private final byte[] hash;

    /**
     * Creates a new Argon2 hash with the given hash and parameters.
     * @param hash The Hash object
     */
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
     * @return The Argon2 type
     */
    public Argon2Type getType() {
        return type;
    }

    /**
     * Returns the version of this hash.
     * @return The version
     */
    public int getVersion() {
        return version;
    }

    /**
     * Returns the memory parameter of this hash.
     * @return The memory parameter
     */
    public int getMemory() {
        return memory;
    }

    /**
     * Returns the iterations parameter of this hash.
     * @return The iterations parameter
     */
    public int getIterations() {
        return iterations;
    }

    /**
     * Returns the parallelism parameter of this hash.
     * @return The parallelism parameter
     */
    public int getParallelism() {
        return parallelism;
    }

    /**
     * Returns the salt of this hash.
     * @return The salt
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Returns the hash.
     * @return The hash
     */
    public byte[] getHash() {
        return hash;
    }

    /**
     * Returns the hash length.
     * @return The hash length
     */
    public int getHashLength() {
        return hash.length;
    }

    /**
     * Returns the hash encoded in hex.
     * @return The encoded hash
     */
    public String toHexHash() {
        return Hex.encodeHexString(hash);
    }

    /**
     * Returns the argon2 hash
     * @return The argon2 hash
     */
    @Override
    public String toString() {
        return toArgon2String();
    }

    /**
     * Returns the argon2 hash
     * @return The argon2 hash
     */
    public String toArgon2String() {
        return Argon2EncodingUtils.encode(this);
    }
}
