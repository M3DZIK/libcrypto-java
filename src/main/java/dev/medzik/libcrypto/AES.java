package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;

/**
 * AES encryption and decryption. Supports AES CBC and GCM modes.
 * <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">See AES on Wikipedia</a>
 */
public class AES {
    /**
     * AES CBC (Cipher Block Chaining) mode.
     */
    public static final AesType CBC = AesType.CBC;
    /**
     * AES GCM (Galois/Counter Mode) mode.
     */
    public static final AesType GCM = AesType.GCM;

    private static final String ALGORITHM = "AES";

    /**
     * Encrypts the given clear text using AES with the given key and random IV.
     * @param type AES type to use
     * @param key secret key to use for encryption (hex encoded)
     * @param clearText clear text to encrypt (UTF-8)
     */
    public static String encrypt(AesType type, String key, String clearText) throws EncryptException {
        try {
            // covert key to byte array
            byte[] keyBytes = Hex.decodeHex(key);

            // generate random IV
            byte[] iv = Salt.generate(type.getIvLength());

            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            AlgorithmParameterSpec parameterSpec = getParameterSpec(type, iv);

            // initialize cipher
            Cipher cipher = Cipher.getInstance(type.getMode());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            // encrypt
            byte[] cipherBytes = cipher.doFinal(clearText.getBytes());

            // return IV + cipher text as hex string
            return Hex.encodeHexString(iv) + Hex.encodeHexString(cipherBytes);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }

    /**
     * Decrypts the given cipher text using AES with the given key.
     * @param type AES type to use
     * @param key secret key to use for decryption (hex encoded)
     * @param cipherText cipher text to decrypt (hex encoded)
     * @return Clear text as string. (UTF-8)
     * @throws EncryptException If the decryption fails.
     */
    public static String decrypt(AesType type, String key, String cipherText) throws EncryptException {
        try {
            // covert key to byte array
            byte[] keyBytes = Hex.decodeHex(key);

            // get IV length in hex string
            int ivLength = type.getIvLength() * 2;

            // extract IV and Cipher Text from hex string
            byte[] iv = Hex.decodeHex(cipherText.substring(0, ivLength));
            byte[] cipherBytes = Hex.decodeHex(cipherText.substring(ivLength));

            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            AlgorithmParameterSpec parameterSpec = getParameterSpec(type, iv);

            // initialize cipher
            Cipher cipher = Cipher.getInstance(type.getMode());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            // decrypt
            byte[] clearBytes = cipher.doFinal(cipherBytes);

            // return clear text as string
            return new String(clearBytes);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }

    private static AlgorithmParameterSpec getParameterSpec(AesType type, byte[] iv) throws EncryptException {
        switch (type) {
            case CBC:
                return new IvParameterSpec(iv);
            case GCM:
                return new GCMParameterSpec(128, iv);
            default:
                throw new EncryptException("Unknown AES type: " + type);
        }
    }

    public enum AesType {
        CBC("AES/CBC/PKCS5Padding", 16),
        GCM("AES/GCM/NoPadding", 12);

        private final String mode;
        private final int ivLength;

        AesType(String mode, int ivLength) {
            this.mode = mode;
            this.ivLength = ivLength;
        }

        public String getMode() {
            return mode;
        }

        public int getIvLength() {
            return ivLength;
        }
    }
}
