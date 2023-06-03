module dev.medzik.libcrypto {
    // Apache Commons Codec
    requires org.apache.commons.codec;

    // Bouncy Castle
    requires org.bouncycastle.provider;

    exports dev.medzik.libcrypto;
}
