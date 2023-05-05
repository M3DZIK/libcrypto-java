package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class RSATests {
    @Test
    void generateKeyPair() throws EncryptException {
        // generate key pair
        KeyPair keyPair = RSA.generateKeyPair(2048);

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
    }

    @Test
    void encryptRsa2048() throws EncryptException {
        // generate key pair
        KeyPair keyPair = RSA.generateKeyPair(2048);

        // encrypt
        String cipherText = RSA.encrypt("Hello World!", keyPair.getPublic());

        assertNotNull(cipherText);
        assertNotEquals("Hello World!", cipherText);
    }

    @Test
    void decryptRsa2048() throws EncryptException {
        // generate key pair
        KeyPair keyPair = RSA.generateKeyPair(2048);

        // encrypt
        String cipherText = RSA.encrypt("Hello World!", keyPair.getPublic());

        // decrypt
        String clearText = RSA.decrypt(cipherText, keyPair.getPrivate());

        assertNotNull(clearText);
        assertEquals("Hello World!", clearText);
    }

    // Keys from openssl.
    //
    // Generated using:
    // openssl genrsa -out keypair.pem 2048
    // openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
    // openssl rsa -in keypair.pem -pubout -out publickey.crt
    //
    // publicKey from pkcs8.key
    // privateKey from keypair.pem

    String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1EyiJAYr2axFDARkA2KP\n" +
            "v59tlszz5uKF6XfiqwjyOiiaHmSsDeVWlUfLpioryll2GtKuM2We0ZjDqOrYWXvU\n" +
            "rOsJQpxkI+2bNuZ8tm69jA2xd10Pujtklgsrl5o7TYvMQRTZzy4JQjLSjXwwllp2\n" +
            "IiE0I1bkQG13COMY3UvlRZNRF3RbtjCITCj6/sgzw7BR4izleCYG91mM8swhIZ1r\n" +
            "ecOB8oCdB36hHaCv3hTrzkCMji2ao+prIFL3ZbJUdLfP/XloFFKiK1+HkkeVnq/9\n" +
            "Bt2je6Dq34+X950VPOsLTeo4cQO2K7GozcFL0Ausab/PJjHz09+z7+PYS3rO1iQ5\n" +
            "8wIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";

    String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDUTKIkBivZrEUM\n" +
            "BGQDYo+/n22WzPPm4oXpd+KrCPI6KJoeZKwN5VaVR8umKivKWXYa0q4zZZ7RmMOo\n" +
            "6thZe9Ss6wlCnGQj7Zs25ny2br2MDbF3XQ+6O2SWCyuXmjtNi8xBFNnPLglCMtKN\n" +
            "fDCWWnYiITQjVuRAbXcI4xjdS+VFk1EXdFu2MIhMKPr+yDPDsFHiLOV4Jgb3WYzy\n" +
            "zCEhnWt5w4HygJ0HfqEdoK/eFOvOQIyOLZqj6msgUvdlslR0t8/9eWgUUqIrX4eS\n" +
            "R5Wer/0G3aN7oOrfj5f3nRU86wtN6jhxA7YrsajNwUvQC6xpv88mMfPT37Pv49hL\n" +
            "es7WJDnzAgMBAAECggEADYlKrVFXamxO2r1M7d+oRWeSQpM+2fHc5/ik6JLhdE6H\n" +
            "xSMAysIHYJf7UX+kMHq+dRIJ2W0ZUJ6U8H2eMyvExmHAwrvbXA8Xs8sZGJNnB+Ri\n" +
            "Sbdn+/qIJ1Opq+OW9GgoKzN7z8yiT9OTE+0J4WGoi/SMsSl71D/RNIKGYKso1eQO\n" +
            "VSNryZn2LPyGZ2lj2SNGHemCNAVPm2WtNWq/U6jE9FjKBz7hPNZIfyf9qHCNDlwS\n" +
            "E2TvQwnXUm9XvbwjZFxNYU8ndXJK6xVdptXQUEKvmO1HhSY5tfTxCgcdTDe7ecBg\n" +
            "MD1JEN1wGaZmGLyVppUVhmiw8o9rCFyILKjFzkMZAQKBgQDguErUHnp4SzRPr+Bo\n" +
            "20sAzwEK4yqFjGwXTN8/66Pu9alAfoUlIa8lTJRsWZEd/DrXNguTwst9M+Lp9KGP\n" +
            "NoLzNw3iBoRQzgiYHAIr19R6J4scPQYlm6zDOH4+5CfqiOrGHVqOedKfbmiQz/v+\n" +
            "wT3NBWnOf/iLxMzE/sDpQjj6AwKBgQDx2b7K636H0WnCwXCo73l08YpGOv7gnmRa\n" +
            "/iXEuALCxzjnwtWJei3pRIUwYIUZ2pyilu1sK4y7gdbXi57VOP9VfPPj33cOYWgL\n" +
            "Td60t86dHeu90xUKcOUuAmtV5cTHzjzBMlMkim1viMVi/z5WY2X73pAmRarbj8Ce\n" +
            "voljbnO1UQKBgBjerIFfQiSQBiEPkOFp65oSTsY6r9kJ2miVvFtho8ntbCbUGb4r\n" +
            "RSv2lrKLExFjecuZkpxuwYCAvosv5LVpzgJGxIWQPRKIStEywFbD0yMVv0KHymdd\n" +
            "HDiaxvYE4BoHvxvf4cbE2reES5RDQFtIXaOUBsqwxPwK8rKWkxj9mDqrAoGAIgVS\n" +
            "XHMiGnLv4LCba3g8aqHrpJN59Rjy3wXvRCvqX4Hs1FVI+ozQVocIAVUihA+HhyuZ\n" +
            "/GRn6JyMH0gJsM7SxDDOkhiGQ+SZ4TU0BdHxY5Ko7cv6orxc0MsQVEX9F2pAi6DL\n" +
            "p1E9sbnYomNrXnWfC/4z4t5b+YTQQMRmyTDpX/ECgYBDn5y/tppestelWHsCjEuT\n" +
            "LEqXHhjR03vyLXxr02sAoZ0xVh2zYQGY6Aq0WKqwwBOh+EHoJPz4YG9Z/cRBaeCe\n" +
            "Gx5JK4WnVXV1OZVRJhqM098Qe2ZJo2mprnGZCEy5LXJtrQNTT+/uNL+/mfr3hleG\n" +
            "z/huP1lAZDmgbZcHWjIXog==\n" +
            "-----END PRIVATE KEY-----\n";

    @Test
    void encryptDecryptWithKeyFromString() throws EncryptException {
        // encrypt
        String cipherText = RSA.encrypt("Hello World!", RSA.KeyUtils.getPublicKey(publicKey));

        // decrypt
        String clearText = RSA.decrypt(cipherText, RSA.KeyUtils.getPrivateKey(privateKey));

        assertNotNull(clearText);
        assertEquals("Hello World!", clearText);
    }

    @Test
    void convertKeysToString() throws EncryptException {
        // convert to string
        String publicKeyOut = RSA.KeyUtils.getPublicKeyString(RSA.KeyUtils.getPublicKey(publicKey));
        String privateKeyOut = RSA.KeyUtils.getPrivateKeyString(RSA.KeyUtils.getPrivateKey(privateKey));

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        assertEquals(publicKey, publicKeyOut);
        assertEquals(privateKey, privateKeyOut);
    }
}
