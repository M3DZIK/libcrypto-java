package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES CBC encryption/decryption with PKCS5 padding and hex encoding.
 */
public class AesGcm {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/GCM/NoPadding";

    /**
     * Encrypts the given clear text using AES-CBC with the given key and random IV.
     * @param key secret key to use for encryption (hex encoded)
     * @param clearText clear text to encrypt (UTF-8)
     * @return Cipher text as hex string.
     * @throws EncryptException If the encryption fails.
     */
    public static String encrypt(String key, String clearText) throws EncryptException {
        try {
            // covert key to byte array
            byte[] keyBytes = Hex.decodeHex(key);

            // generate random IV
            byte[] iv = Salt.generate(12);

            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

            // initialize cipher
            Cipher cipher = Cipher.getInstance(MODE);
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
     * Decrypts the given cipher text using AES-CBC with the given key.
     * @param key secret key to use for decryption (hex encoded)
     * @param cipherText cipher text to decrypt (hex encoded)
     * @return Clear text as string. (UTF-8)
     * @throws EncryptException If the decryption fails.
     */
    public static String decrypt(String key, String cipherText) throws EncryptException {
        try {
            // covert key to byte array
            byte[] keyBytes = Hex.decodeHex(key);

            // extract IV and Cipher Text from hex string
            byte[] iv = Hex.decodeHex(cipherText.substring(0, 24));
            byte[] cipherBytes = Hex.decodeHex(cipherText.substring(24));

            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

            // initialize cipher
            Cipher cipher = Cipher.getInstance(MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            // decrypt
            byte[] clearBytes = cipher.doFinal(cipherBytes);

            // return clear text as string
            return new String(clearBytes);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }
}
