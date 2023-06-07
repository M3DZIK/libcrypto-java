module dev.medzik.libcrypto {
    // Apache Commons Codec (used for hex encoding)
    requires org.apache.commons.codec;

    // Password4j (used for argon2 implementation)
    requires password4j;

    // Curve25519 implementation
    requires curve25519.java;

    exports dev.medzik.libcrypto;
}
