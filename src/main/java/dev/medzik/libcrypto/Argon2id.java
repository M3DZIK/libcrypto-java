package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Argon2id {
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
     * Creates a new Argon2id instance.
     * @param hashLength the length of the hash in bytes
     * @param parallelism the number of parallel threads to use when hashing
     * @param memory the amount of memory to use when hashing, in KiB
     * @param iterations the number of iterations to use when hashing
     */
    public Argon2id(int hashLength, int parallelism, int memory, int iterations) {
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
    }

    /**
     * Hashes a password using Argon2id.
     * @param password the password to hash
     * @param salt the salt to use
     * @return the hashed password
     */
    public String hash(String password, byte[] salt) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13) // 19
                .withIterations(iterations)
                .withMemoryAsKB(memory)
                .withParallelism(parallelism)
                .withSalt(salt);
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(builder.build());
        byte[] result = new byte[hashLength];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), result, 0, result.length);

        return Argon2EncodingUtils.encode(result, builder.build());
    }

    /**
     * Verifies a password against a hash.
     * @param rawPassword the raw password to verify
     * @param encodedPassword the encoded password to verify against
     * @return true if the passwords match, false otherwise
     * @throws IOException if the password hash is malformed
     */
    public static boolean verify(CharSequence rawPassword, String encodedPassword) throws IOException {
        if (encodedPassword == null) {
            throw new IOException("password hash is null");
        }

        Argon2EncodingUtils.Argon2Hash decoded;
        try {
            decoded = Argon2EncodingUtils.decode(encodedPassword);
        } catch (IllegalArgumentException ex) {
            throw new IOException("Malformed password hash", ex);
        }

        byte[] hashBytes = new byte[decoded.getHash().length];
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(decoded.getParameters());
        generator.generateBytes(rawPassword.toString().toCharArray(), hashBytes);
        return constantTimeArrayEquals(decoded.getHash(), hashBytes);
    }

    /**
     * Convert hash to hex string. Useful for AES encryption.
     * @param hash the hash to convert
     * @return the hex string
     */
    public static String toHexHash(String hash) {
        Argon2EncodingUtils.Argon2Hash decoded = Argon2EncodingUtils.decode(hash);
        return Hex.encodeHexString(decoded.getHash());
    }

    /**
     * Constant time comparison to prevent against timing attacks. Copied from Spring Security.
     */
    private static boolean constantTimeArrayEquals(byte[] expected, byte[] actual) {
        if (expected.length != actual.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < expected.length; i++) {
            result |= expected[i] ^ actual[i];
        }
        return result == 0;
    }
}
