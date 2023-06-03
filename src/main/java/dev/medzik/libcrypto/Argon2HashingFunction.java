package dev.medzik.libcrypto;

import com.password4j.Argon2Function;
import com.password4j.Hash;
import com.password4j.Password;

/**
 * A hashing function for Argon2.
 */
public class Argon2HashingFunction {
    private final int hashLength;
    private final int parallelism;
    private final int memory;
    private final int iterations;
    private final Argon2Type type;
    private final int version;

    private static final int DEFAULT_VERSION = 19;

    public static class Builder {
        private int hashLength;
        private int parallelism;
        private int memory;
        private int iterations;
        private Argon2Type type;
        private int version;

        public Builder() {
            this.hashLength = 32;
            this.parallelism = 1;
            this.memory = 65536;
            this.iterations = 3;
            this.type = Argon2Type.ID;
            this.version = DEFAULT_VERSION;
        }

        public Builder setHashLength(int hashLength) {
            this.hashLength = hashLength;
            return this;
        }

        public Builder setParallelism(int parallelism) {
            this.parallelism = parallelism;
            return this;
        }

        public Builder setMemory(int memory) {
            this.memory = memory;
            return this;
        }

        public Builder setIterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        public Builder setType(Argon2Type type) {
            this.type = type;
            return this;
        }

        public Builder setVersion(int version) {
            this.version = version;
            return this;
        }

        public Argon2HashingFunction build() {
            return new Argon2HashingFunction(hashLength, parallelism, memory, iterations, type, version);
        }
    }

    /**
     * Creates a new instance.
     * @param hashLength The length of the hash in bytes
     * @param parallelism The number of parallel threads to use when hashing
     * @param memory The amount of memory to use when hashing, in KiB
     * @param iterations The number of iterations to use when hashing
     */
    public Argon2HashingFunction(int hashLength, int parallelism, int memory, int iterations, Argon2Type type, int version) {
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
        this.type = type;
        this.version = version;
    }

    /**
     * Creates a new instance.
     * @param hashLength The length of the hash in bytes
     * @param parallelism The number of parallel threads to use when hashing
     * @param memory The amount of memory to use when hashing, in KiB
     * @param iterations The number of iterations to use when hashing
     */
    public Argon2HashingFunction(int hashLength, int parallelism, int memory, int iterations) {
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
        this.type = Argon2Type.ID;
        this.version = DEFAULT_VERSION;
    }

    /**
     * Hashes a password using Argon2id.
     * @param password The password to hash
     * @param salt The salt to use
     * @return The hashed password
     */
    public Argon2Hash hash(String password, byte[] salt) {
        Argon2Function instance = Argon2Function.getInstance(memory, iterations, parallelism, hashLength, type.toPassword4jType(), version);

        Hash hash = Password
                .hash(password)
                .addSalt(salt)
                .with(instance);

        return Argon2EncodingUtils.decode(hash.getResult());
    }

    /**
     * Hashes a password using Argon2id.
     * @param password The password to hash
     * @param salt The salt to use
     * @return The hashed password
     */
    public Argon2Hash hash(String password, String salt) {
       return hash(password, salt.getBytes());
    }

    /**
     * Verifies a password against a hash.
     * @param rawPassword The raw password to verify
     * @param encodedPassword The encoded password to verify against
     * @return True if the passwords match, false otherwise
     */
    public static boolean verify(CharSequence rawPassword, String encodedPassword) {
        Argon2Hash argon2Hash = Argon2EncodingUtils.decode(encodedPassword);

        Argon2Function instance = Argon2Function.getInstance(argon2Hash.getMemory(), argon2Hash.getIterations(), argon2Hash.getParallelism(), argon2Hash.getHashLength(), argon2Hash.getType().toPassword4jType(), argon2Hash.getVersion());

        return Password
                .check(rawPassword, encodedPassword)
                .with(instance);
    }
}
