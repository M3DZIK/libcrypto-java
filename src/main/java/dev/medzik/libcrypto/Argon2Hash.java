package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.params.Argon2Parameters;

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
     * Creates a new Argon2Hash with the given parameters.
     * @param type The Argon2 type
     * @param version The version of argon2
     * @param memory The memory parameter
     * @param iterations The iterations parameter
     * @param parallelism The parallelism parameter
     * @param salt The salt as a byte array
     * @param hash The hash as a byte array
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
     * Creates a new Argon2Hash with the given hash and parameters.
     * @param hash The hash as a byte array
     * @param parameters The parameters of the hash
     */
    public Argon2Hash(byte[] hash, Argon2Parameters parameters) {
        this.hash = hash;

        // from Argon2Parameters
        this.type = Argon2Type.fromOrdinal(parameters.getType());
        this.version = parameters.getVersion();
        this.memory = parameters.getMemory();
        this.iterations = parameters.getIterations();
        this.parallelism = parameters.getLanes();
        this.salt = parameters.getSalt();
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
        return toArgon2Hash();
    }

    /**
     * Returns the argon2 hash
     * @return The argon2 hash
     */
    public String toArgon2Hash() {
        return Argon2EncodingUtils.encode(this);
    }

    /**
     * Compares this hash to the given hash.
     * @param hash The hash to compare to
     * @return Whether the hashes are equal
     */
    public boolean equals(Argon2Hash hash) {
        return toArgon2Hash().equals(hash.toArgon2Hash());
    }
}
