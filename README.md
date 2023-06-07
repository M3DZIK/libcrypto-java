A cryptography utilities for Java

## Documentation

### Installation

The library is available on Maven Central. To use it, add the following to your `pom.xml` file:

```xml
<dependency>
    <groupId>dev.medzik</groupId>
    <artifactId>libcrypto</artifactId>
    <version>0.4.0</version>
</dependency>
```

### Usage

#### Hashing Passwords

Hash passwords using Argon2 (recommended)

![Screenshot with an example argon2 hashing code](https://github.com/M3DZIK/libcrypto-java/assets/87065584/4a125e5e-4950-456a-a89e-cca56d4f8868)

Or use PBKDF2

![Screenshot with an example PBKDF2 hashing code](https://user-images.githubusercontent.com/87065584/236326073-3cad8efe-a1db-4320-943c-59d53f1976c2.png)

#### Encrypting Data

Encrypt data using AES CBC

![Screenshot with an example code of AES CBC](https://github.com/M3DZIK/libcrypto-java/assets/87065584/9b645be4-c30a-4bd6-a7f9-03ae7468536f)

Encrypt data using RSA

![Screenshot with an example code of RSA](https://user-images.githubusercontent.com/87065584/236550078-562027d9-655b-47c8-8ae5-3f4e9c1067af.png)

Encrypt data between two users using Curve25519

![Screenshot with an example code of Curve25519](https://github.com/M3DZIK/libcrypto-java/assets/87065584/842941d1-ffc7-4ccd-90c4-aa3857679d5d)
