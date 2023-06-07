package dev.medzik.libcrypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA encryption/decryption with PKCS5 padding and base64 encoding.
 */
public class RSA {
    private static final String ALGORITHM = "RSA";

    /**
     * Generates a new RSA key pair.
     * @param keySize key size in bits
     * @return Generated key pair.
     * @throws EncryptException If the key pair generation fails.
     */
    public static KeyPair generateKeyPair(int keySize) throws EncryptException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(keySize);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }

    /**
     * Encrypts the given clear text using RSA with the given public key.
     * @param clearText clear text to encrypt
     * @param publicKey public key to use for encryption
     * @return Cipher text as base64 string.
     * @throws EncryptException If the encryption fails.
     */
    public static String encrypt(String clearText, PublicKey publicKey) throws EncryptException {
        try {
            // initialize cipher
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // encrypt
            byte[] cipherBytes = cipher.doFinal(clearText.getBytes());

            // return cipher text as base64 string
            return Base64.encodeBase64String(cipherBytes);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }

    /**
     * Decrypts the given cipher text using RSA with the given private key.
     * @param cipherText cipher text to decrypt
     * @param privateKey private key to use for decryption
     * @return Clear text as string. (UTF-8)
     * @throws EncryptException If the decryption fails.
     */
    public static String decrypt(String cipherText, PrivateKey privateKey) throws EncryptException {
        try {
            // initialize cipher
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // decrypt
            byte[] clearBytes = cipher.doFinal(Base64.decodeBase64(cipherText));

            // return clear text
            return new String(clearBytes);
        } catch (Exception e) {
            throw new EncryptException(e);
        }
    }

    public static class KeyUtils {
        /**
         * Get openssl compatible public key string.
         * @param publicKey public key
         * @return Public key string. (openssl compatible)
         */
        public static String getPublicKeyString(PublicKey publicKey) {
            // encode to base64 and add new lines every 64 characters according to openssl format
            String publicKeyB64 = newLineEvery64Characters(Base64.encodeBase64String(publicKey.getEncoded()));

            // return in openssl compatible format
            return "-----BEGIN PUBLIC KEY-----\n" + publicKeyB64 + "\n-----END PUBLIC KEY-----\n";
        }

        /**
         * Get openssl compatible private key string.
         * @param privateKey private key
         * @return Private key string. (openssl compatible) (PKCS8)
         */
        public static String getPrivateKeyString(PrivateKey privateKey) {
            // encode to base64 and add new lines every 64 characters according to openssl format
            String privateKeyB64 = newLineEvery64Characters(Base64.encodeBase64String(privateKey.getEncoded()));

            // return in openssl compatible format
            return "-----BEGIN PRIVATE KEY-----\n" + privateKeyB64 + "\n-----END PRIVATE KEY-----\n";
        }

        /**
         * Get public key from byte array. (X509)
         * @param publicKey public key byte array
         * @return Public key.
         * @throws EncryptException If the public key is invalid.
         */
        public static PublicKey getPublicKey(byte[] publicKey) throws EncryptException {
            try {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
                KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
                return keyFactory.generatePublic(keySpec);
            } catch (Exception e) {
                throw new EncryptException(e);
            }
        }

        /**
         * Get public key from string. (X509)
         * @param publicKey public key string
         * @return Public key.
         * @throws EncryptException If the public key is invalid.
         */
        public static PublicKey getPublicKey(String publicKey) throws EncryptException {
            // remove header and footer
            publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----\n", "");
            publicKey = publicKey.replace("-----END PUBLIC KEY-----", "");

            // remove new lines

            // decode base64
            byte[] publicKeyBytes = Base64.decodeBase64(publicKey);

            // get public key
            return getPublicKey(publicKeyBytes);
        }

        /**
         * Get private key from byte array. (PKCS8)
         * @param privateKey private key byte array
         * @return Private key.
         * @throws EncryptException If the private key is invalid.
         */
        public static PrivateKey getPrivateKey(byte[] privateKey) throws EncryptException {
            try {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
                KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
                return keyFactory.generatePrivate(keySpec);
            } catch (Exception e) {
                throw new EncryptException(e);
            }
        }

        /**
         * Get private key from string. (PKCS8)
         * @param privateKey private key string
         * @return Private key.
         * @throws EncryptException If the private key is invalid.
         */
        public static PrivateKey getPrivateKey(String privateKey) throws EncryptException {
            // remove header and footer
            privateKey = privateKey.replace("-----BEGIN PRIVATE KEY-----\n", "");
            privateKey = privateKey.replace("-----END PRIVATE KEY-----", "");

            // remove new lines
            privateKey = privateKey.replace("\n", "");

            // decode base64
            byte[] privateKeyBytes = Base64.decodeBase64(privateKey);

            // get private key
            return getPrivateKey(privateKeyBytes);
        }


        /**
         * Add new line every 64 characters. (according to openssl format)
         * @param string string to add new lines
         * @return String with new lines every 64 characters.
         */
        private static String newLineEvery64Characters(String string) {
            StringBuilder stringBuilder = new StringBuilder();

            for (int i = 0; i < string.length(); i++) {
                stringBuilder.append(string.charAt(i));

                if ((i + 1) % 64 == 0) {
                    stringBuilder.append("\n");
                }
            }

            return stringBuilder.toString();
        }
    }
}
