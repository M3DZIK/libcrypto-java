package dev.medzik.libcrypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;

/**
 * A hashing function for Argon2.
 */
public class Argon2HashingFunction {
    /**
     * The length of the hash in bytes.
     * <p>
     * e.g. 32 for 256-bit hash. (256 / 8) (Use it for AES encryption)
     */
    private final int hashLength;
    /**
     * The number of parallel threads to use when hashing.
     */
    private final int parallelism;
    /**
     * The amount of memory to use when hashing, in KiB.
     * <p>
     * e.g. 65536 for 64 MiB.
     */
    private final int memory;
    /**
     * The number of iterations to use when hashing.
     */
    private final int iterations;
    /**
     * The type of Argon2 to use.
     */
    private final Argon2Type type;
    /**
     * The version of Argon2 to use.
     * Default is 19
     */
    private final int version;

    /**
     * The default version of Argon2 to use.
     */
    private static final int DEFAULT_VERSION = 19;

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
        // create the parameters for the hash
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(type.ordinal())
                .withVersion(version)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterations)
                .withSalt(salt);
        Argon2Parameters parameters = builder.build();

        // create a new instance of the hashing function
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);

        // initialize the hash array
        byte[] hash = new byte[hashLength];

        // hash the password
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), hash);

        // return the hash and parameters
        return new Argon2Hash(hash, parameters);
    }

    /**
     * Verifies a password against a hash.
     * @param rawPassword The raw password to verify
     * @param encodedPassword The encoded password to verify against
     * @return True if the passwords match, false otherwise
     */
    public static boolean verify(CharSequence rawPassword, String encodedPassword) {
        // decode the hash
        Argon2Hash argon2Hash = Argon2EncodingUtils.decode(encodedPassword);

        // create a new instance of the hashing function
        Argon2HashingFunction instance = new Argon2HashingFunction(
                argon2Hash.getHashLength(),
                argon2Hash.getParallelism(),
                argon2Hash.getMemory(),
                argon2Hash.getIterations(),
                argon2Hash.getType(),
                argon2Hash.getVersion()
        );

        // hash the raw password with the salt from the encoded password
        Argon2Hash hash = instance.hash(rawPassword.toString(), argon2Hash.getSalt());

        // compare the hashes
        return hash.equals(argon2Hash);
    }
}
