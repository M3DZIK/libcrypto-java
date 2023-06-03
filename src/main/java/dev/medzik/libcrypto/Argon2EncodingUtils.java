package dev.medzik.libcrypto;

import com.password4j.types.Argon2;

import java.util.Base64;

/**
 * Utility class for encoding and decoding Argon2 hashes.
 */
public class Argon2EncodingUtils {
    private static final Base64.Encoder b64encoder = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder b64decoder = Base64.getDecoder();

    /**
     * Encodes the given hash and parameters to a string.
     * @param hash The hash to encode
     * @return Argon2 encoded hash
     * @throws IllegalArgumentException If the parameters contain invalid values
     */
    public static String encode(Argon2Hash hash) throws IllegalArgumentException {
        StringBuilder stringBuilder = new StringBuilder();

        switch (hash.getType()) {
            case D:
                stringBuilder.append("$argon2d");
                break;
            case I:
                stringBuilder.append("$argon2i");
                break;
            case ID:
                stringBuilder.append("$argon2id");
                break;
        }

        stringBuilder.append("$v=").append(hash.getVersion()).append("$m=").append(hash.getMemory())
                .append(",t=").append(hash.getIterations()).append(",p=").append(hash.getParallelism());

        if (hash.getSalt() != null) {
            stringBuilder.append("$").append(b64encoder.encodeToString(hash.getSalt()));
        }

        stringBuilder.append("$").append(b64encoder.encodeToString(hash.getHash()));
        return stringBuilder.toString();
    }

    /**
     * Decodes the given Argon2 encoded hash to a {@link Argon2Hash} object.
     * @param encodedHash The encoded argon2 hash
     * @return The decoded hash
     * @throws IllegalArgumentException If the encoded hash is invalid
     */
    public static Argon2Hash decode(String encodedHash) throws IllegalArgumentException {
        String[] parts = encodedHash.split("\\$");
        if (parts.length < 4) {
            throw new IllegalArgumentException("Invalid encoded Argon2-hash");
        }

        int currentPart = 1;
        Argon2Type type;
        switch (parts[currentPart++]) {
            case "argon2d":
                type = Argon2Type.D;
                break;
            case "argon2i":
                type = Argon2Type.I;
                break;
            case "argon2id":
                type = Argon2Type.ID;
                break;
            default:
                throw new IllegalArgumentException("Invalid algorithm type: " + parts[0]);
        }

        int version;
        if (parts[currentPart].startsWith("v=")) {
            version = Integer.parseInt(parts[currentPart].substring(2));
            currentPart++;
        } else {
            throw new IllegalArgumentException("Invalid version parameter");
        }

        String[] performanceParams = parts[currentPart++].split(",");

        if (performanceParams.length != 3) {
            throw new IllegalArgumentException("Amount of performance parameters invalid");
        }

        if (!performanceParams[0].startsWith("m=")) {
            throw new IllegalArgumentException("Invalid memory parameter");
        }

        int memory = Integer.parseInt(performanceParams[0].substring(2));
        if (!performanceParams[1].startsWith("t=")) {
            throw new IllegalArgumentException("Invalid iterations parameter");
        }

        int iterations = Integer.parseInt(performanceParams[1].substring(2));
        if (!performanceParams[2].startsWith("p=")) {
            throw new IllegalArgumentException("Invalid parallelity parameter");
        }

        int parallelism = Integer.parseInt(performanceParams[2].substring(2));
        byte[] salt = b64decoder.decode(parts[currentPart++]);
        byte[] hash = b64decoder.decode(parts[currentPart]);

        return new Argon2Hash(type, version, memory, iterations, parallelism, salt, hash);
    }
}
