package dev.medzik.libcrypto;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;

import java.util.Base64;

public class Argon2EncodingUtils {
    private static final Base64.Encoder b64encoder = Base64.getEncoder().withoutPadding();

    private static final Base64.Decoder b64decoder = Base64.getDecoder();

    public static String encode(byte[] hash, Argon2Parameters parameters) throws IllegalArgumentException {
        StringBuilder stringBuilder = new StringBuilder();
        switch (parameters.getType()) {
            case Argon2Parameters.ARGON2_d:
                stringBuilder.append("$argon2d");
                break;
            case Argon2Parameters.ARGON2_i:
                stringBuilder.append("$argon2i");
                break;
            case Argon2Parameters.ARGON2_id:
                stringBuilder.append("$argon2id");
                break;
            default:
                throw new IllegalArgumentException("Invalid algorithm type: " + parameters.getType());
        }
        stringBuilder.append("$v=").append(parameters.getVersion()).append("$m=").append(parameters.getMemory())
                .append(",t=").append(parameters.getIterations()).append(",p=").append(parameters.getLanes());
        if (parameters.getSalt() != null) {
            stringBuilder.append("$").append(b64encoder.encodeToString(parameters.getSalt()));
        }
        stringBuilder.append("$").append(b64encoder.encodeToString(hash));
        return stringBuilder.toString();
    }

    public static Argon2Hash decode(String encodedHash) throws IllegalArgumentException {
        Argon2Parameters.Builder paramsBuilder;
        String[] parts = encodedHash.split("\\$");
        if (parts.length < 4) {
            throw new IllegalArgumentException("Invalid encoded Argon2-hash");
        }
        int currentPart = 1;
        switch (parts[currentPart++]) {
            case "argon2d":
                paramsBuilder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_d);
                break;
            case "argon2i":
                paramsBuilder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i);
                break;
            case "argon2id":
                paramsBuilder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id);
                break;
            default:
                throw new IllegalArgumentException("Invalid algorithm type: " + parts[0]);
        }
        if (parts[currentPart].startsWith("v=")) {
            paramsBuilder.withVersion(Integer.parseInt(parts[currentPart].substring(2)));
            currentPart++;
        }
        String[] performanceParams = parts[currentPart++].split(",");
        if (performanceParams.length != 3) {
            throw new IllegalArgumentException("Amount of performance parameters invalid");
        }
        if (!performanceParams[0].startsWith("m=")) {
            throw new IllegalArgumentException("Invalid memory parameter");
        }
        paramsBuilder.withMemoryAsKB(Integer.parseInt(performanceParams[0].substring(2)));
        if (!performanceParams[1].startsWith("t=")) {
            throw new IllegalArgumentException("Invalid iterations parameter");
        }
        paramsBuilder.withIterations(Integer.parseInt(performanceParams[1].substring(2)));
        if (!performanceParams[2].startsWith("p=")) {
            throw new IllegalArgumentException("Invalid parallelity parameter");
        }
        paramsBuilder.withParallelism(Integer.parseInt(performanceParams[2].substring(2)));
        paramsBuilder.withSalt(b64decoder.decode(parts[currentPart++]));
        return new Argon2Hash(b64decoder.decode(parts[currentPart]), paramsBuilder.build());
    }

//    public static Argon2Hash decode(String hash) {
//        String[] parts = hash.split("\\$");
//
//        if (parts.length != 6) {
//            throw new IllegalArgumentException("Invalid hash");
//        }
//
//        if (!"argon2id".equals(parts[1])) {
//            throw new IllegalArgumentException("Invalid hash");
//        }
//
//        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id);
//
//        for (String part : parts[2].split(",")) {
//            String[] kv = part.split("=");
//
//            if (kv.length != 2) {
//                throw new IllegalArgumentException("Invalid hash");
//            }
//
//            switch (kv[0]) {
//                case "v":
//                    builder.withVersion(Integer.parseInt(kv[1]));
//                    break;
//                case "m":
//                    builder.withMemoryAsKB(Integer.parseInt(kv[1]));
//                    break;
//                case "t":
//                    builder.withIterations(Integer.parseInt(kv[1]));
//                    break;
//                case "p":
//                    builder.withParallelism(Integer.parseInt(kv[1]));
//                    break;
//                default:
//                    throw new IllegalArgumentException("Invalid hash");
//            }
//        }
//
//        byte[] salt = b64decoder.decode(parts[3]);
//        byte[] hashBytes = b64decoder.decode(parts[4]);
//
//        return new Argon2Hash(hashBytes, builder.build());
//    }

    public static class Argon2Hash {

        private byte[] hash;

        private Argon2Parameters parameters;

        Argon2Hash(byte[] hash, Argon2Parameters parameters) {
            this.hash = Arrays.clone(hash);
            this.parameters = parameters;
        }

        public byte[] getHash() {
            return Arrays.clone(this.hash);
        }

        public void setHash(byte[] hash) {
            this.hash = Arrays.clone(hash);
        }

        public Argon2Parameters getParameters() {
            return this.parameters;
        }

        public void setParameters(Argon2Parameters parameters) {
            this.parameters = parameters;
        }

    }
}
