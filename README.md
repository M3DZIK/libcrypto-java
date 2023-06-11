A cryptography utilities for Java

## Documentation

### Installation

The library is available on Maven Central. To use it, add the following to your `pom.xml` file:

```xml
<dependency>
    <groupId>dev.medzik</groupId>
    <artifactId>libcrypto</artifactId>
    <version>0.5.2</version>
</dependency>
```

### Usage

#### Hash the password

**Argon2** (recommended)

![Argon2 hashing example](https://github.com/M3DZIK/libcrypto-java/assets/87065584/139edc3c-9937-4df8-8af3-50a4bf3679d6)

**PBKDF2**

![PBKDF2 hashing example](https://user-images.githubusercontent.com/87065584/236326073-3cad8efe-a1db-4320-943c-59d53f1976c2.png)

#### Encrypting Data

**AES**

![AES GCM encryption with argon2id](https://github.com/M3DZIK/libcrypto-java/assets/87065584/ad511e04-ff67-4336-8600-1969e9eca142)

**RSA**

![RSA encryption](https://user-images.githubusercontent.com/87065584/236550078-562027d9-655b-47c8-8ae5-3f4e9c1067af.png)

#### Exchange keys with Diffie-Hellman

![Diffie-Hellman key exchange](https://github.com/M3DZIK/libcrypto-java/assets/87065584/c3e3d1fa-9a64-4739-a421-0fe4b0abca29)
