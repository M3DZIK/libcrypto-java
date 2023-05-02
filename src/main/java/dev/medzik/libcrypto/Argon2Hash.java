package dev.medzik.libcrypto;

import com.password4j.types.Argon2;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * Represents an Argon2 hash with its parameters.
 */
public class Argon2Hash {
    private final Argon2 type;
    private final int version;
    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final byte[] salt;
    private final byte[] hash;

    /**
     * Creates a new Argon2 hash with the given hash and parameters.
     * @param hash The Hash object
     */
    public Argon2Hash(Argon2 type, int version, int memory, int iterations, int parallelism, byte[] salt, byte[] hash) {
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
    public Argon2 getType() {
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
        return Argon2EncodingUtils.encode(this);
    }
}
