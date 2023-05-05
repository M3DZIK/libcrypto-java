A cryptography utilities for Java

## Documentation

### Installation

The library is available on Maven Central. To use it, add the following to your `pom.xml` file:

```xml
<dependency>
    <groupId>dev.medzik</groupId>
    <artifactId>libcrypto</artifactId>
    <version>0.3.0</version>
</dependency>
```

### Usage

#### Hashing Passwords

Hash passwords using Argon2 (recommended)

![Screenshot with an example argon2 hashing code](https://user-images.githubusercontent.com/87065584/236322588-57e81583-ae23-439b-ab0d-d196f926fc5b.png)

Or use PBKDF2

![Screenshot with an example PBKDF2 hashing code](https://user-images.githubusercontent.com/87065584/236326073-3cad8efe-a1db-4320-943c-59d53f1976c2.png)

#### Encrypting Data

Encrypt data using AES CBC

![Screenshot with an example code of AES CBC](https://user-images.githubusercontent.com/87065584/236325358-8982b9c6-cea5-4cb6-a4e2-b81b4e51c163.png)

Encrypt data using RSA

![Screenshot with an example code of RSA](https://user-images.githubusercontent.com/87065584/236550078-562027d9-655b-47c8-8ae5-3f4e9c1067af.png)
