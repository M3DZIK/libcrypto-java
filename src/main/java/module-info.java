module dev.medzik.libcrypto {
    // Apache Commons Codec (used for hex encoding)
    requires org.apache.commons.codec;

    // Password4j (used for argon2 implementation)
    requires password4j;

    // Google Tink (used for Curve25519 implementation)
    requires com.google.crypto.tink;

    exports dev.medzik.libcrypto;
}
