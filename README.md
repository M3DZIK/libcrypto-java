A cryptography utilities for Java

## Installation

### Maven

**Step 1.** Add the JitPack repository to your build file

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

**Step 2.** Add the dependency

```xml
<dependency>
    <groupId>com.github.MedzikUser</groupId>
    <artifactId>libcrypto-java</artifactId>
    <version>v0.1.1</version>
</dependency>
```

### Gradle

**Step 1.** Add the JitPack repository to your build file

```groovy
allprojects {
    repositories {
        // ...
        maven { url 'https://jitpack.io' }
    }
}
```

**Step 2.** Add the dependency

```groovy
dependencies {
    implementation 'com.github.MedzikUser:libcrypto-java:v0.1.1'
}
```
