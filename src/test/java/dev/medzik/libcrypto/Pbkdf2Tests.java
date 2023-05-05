package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class Pbkdf2Tests {
    String password = "hello world";
    byte[] salt = "salt".getBytes();

    @Test
    void sha256() throws EncryptException {
        Pbkdf2 hasher = new Pbkdf2(1000);
        String hash = hasher.sha256(password, salt);

        assertEquals(hash, "27426946a796b9a62bc53fba7157961905e4bdd0af2203d6eaf6dd4b64942def");
    }

    @Test
    void sha512() throws EncryptException {
        Pbkdf2 hasher = new Pbkdf2(1000);
        String hash = hasher.sha512(password, salt);

        assertEquals(hash, "883f5fb301ff684a2e92fdfc1754241bb2dd3eb6af53e5bd7e6c9eb2df7ccb7783f40872b5d3dd5c2915a519f008a92c4c2093e8a589e59962cf1e33c8706ca9");
    }
}
