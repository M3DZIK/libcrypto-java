package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-SHA256/512 hashing.
 * <a href="https://en.wikipedia.org/wiki/PBKDF2">See PBKDF2 on Wikipedia</a>
 */
public class Pbkdf2 {
    /**
     * Number of iterations for the hashing.
     */
    int iterations;

    public Pbkdf2(int passwordIterations) {
        iterations = passwordIterations;
    }

    /**
     * Compute a PBKDF2-SHA256 hash
     * @param password Input password to be hashed.
     * @param salt The password salt.
     * @return 256-bit password hash encoded as hex string.
     * @throws EncryptException If the hashing fails.
     */
    public String sha256(String password, byte[] salt) throws EncryptException {
        return hash("PBKDF2WithHmacSHA256", 256, password, salt);
    }

    /**
     * Compute a PBKDF2-SHA512 hash
     * @param password Input password to be hashed.
     * @param salt The password salt.
     * @return 512-bit password hash encoded as hex string.
     * @throws EncryptException If the hashing fails.
     */
    public String sha512(String password, byte[] salt) throws EncryptException {
        return hash("PBKDF2WithHmacSHA512", 512, password, salt);
    }

    private String hash(String algorithm, int keyLength, String password, byte[] salt) throws EncryptException {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);

            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();

            return Hex.encodeHexString(res);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }
}
