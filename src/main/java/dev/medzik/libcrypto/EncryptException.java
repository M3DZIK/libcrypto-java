package dev.medzik.libcrypto;

/**
 * Exception thrown when an error occurs during encryption or decryption.
 */
public class EncryptException extends Exception {
    public EncryptException(Throwable cause) {
        super(cause);
    }
}
