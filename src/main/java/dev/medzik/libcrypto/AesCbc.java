package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCbc {
    private static final String ALGORITHM = "AES";

    /**
     * Encrypts the given clear text using AES-CBC with the given key and random IV.
     * @param clearText The clear text to encrypt.
     * @param key The key to use for encryption. (must be 256-bit/32-byte)
     * @return The cipher text as hex string.
     * @throws EncryptException If the encryption fails.
     */
    public static String encrypt(String clearText, String key) throws EncryptException {
        try {
            byte[] keyByte = Hex.decodeHex(key);

            if (keyByte.length != 32) {
                throw new IllegalArgumentException("Secret key must be 32 bytes long");
            }

            byte[] iv = new Salt().generate(16);

            SecretKeySpec secretKey = new SecretKeySpec(keyByte, ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

            byte[] cipherBytes = cipher.doFinal(clearText.getBytes());

            return Hex.encodeHexString(iv) + Hex.encodeHexString(cipherBytes);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }

    /**
     * Decrypts the given cipher text using AES-CBC with the given key.
     * @param key The key to use for decryption. (must be 256-bit/32-byte)
     * @param cipherText The cipher text to decrypt.
     * @return The clear text.
     * @throws EncryptException If the decryption fails.
     */
    public static String decrypt(String cipherText, String key) throws EncryptException {
        try {
            byte[] keyByte = Hex.decodeHex(key);

            if (keyByte.length != 32) {
                throw new IllegalArgumentException("Secret key must be 32 bytes long");
            }

            byte[] iv = Hex.decodeHex(cipherText.substring(0, 32));

            byte[] cipherBytes = Hex.decodeHex(cipherText.substring(32));

            SecretKeySpec secretKey = new SecretKeySpec(keyByte, ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            byte[] clearBytes = cipher.doFinal(cipherBytes);

            return new String(clearBytes);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }
}
