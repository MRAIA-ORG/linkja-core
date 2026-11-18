# linkja-core

This project contains classes shared across the linkja applications. Additional documentation is also provided regarding implementations regarding  [encryption](#encryption), and [exception handling](#exception-handling).

## Building
linkja-core needs Java 25 (e.g. [Eclipse Temurin](https://adoptium.net/)) and [Maven](https://maven.apache.org/).

The tests call the linkja C library, so compile it first from the `develop` branch of [linkja-crypto](https://github.com/MRAIA-ORG/linkja-crypto). It needs OpenSSL 3 and CMake (e.g. `brew install openssl@3 cmake`). From a linkja-crypto clone beside this one:

```
mvn install -DskipTests
cmake . -DINCLUDE_SECRETS=OFF -DCMAKE_BUILD_TYPE=Release
make linkjacrypto
```

Then, from this folder:

`mvn clean package -Dnative.lib.dir=../linkja-crypto/target`

This compiles the code, runs all unit tests, and puts the JAR in the `target` folder, e.g. `target/linkja-core-2.0.0-SNAPSHOT.jar`. If you do not give `native.lib.dir`, the tests look for the library in the `lib` folder.

With the public build, one test skips: `NativeCryptoSecretsTest`. It calls `createSecureHash`, the one function that needs the secret. To run it, compile the C library with the published test secret from [linkja-test-data](https://github.com/MRAIA-ORG/linkja-test-data). From a linkja-crypto clone, with a linkja-test-data clone beside it:

```
mvn install -DskipTests
cp ../linkja-test-data/crypto/secret/linkja_secret.h src/include/
cmake . -DINCLUDE_SECRETS=ON -DCMAKE_BUILD_TYPE=Release
cmp ../linkja-test-data/crypto/secret/linkja_secret.h src/include/linkja_secret.h
make linkjacrypto
```

`cmp` prints nothing when the test secret is in place. Keep `-DINCLUDE_SECRETS=ON` in the command. Without it, a clone that made the public build keeps `OFF` and the test still skips. Then run the same `mvn clean package` command. No test skips.

CI runs the same steps on each pull request. See `.github/workflows/ci.yml`.


## Deploying to Maven Repository
Linkja uses the [linkja-mvn-repo](https://github.com/MRAIA-ORG/linkja-mvn-repo) GitHub repository as its Maven repository for project builds.

The associated linkja projects that use linka-core will contain a reference to the GitHub repository in their pom.xml file.  Updates will need to be made to the linkja-mvn-repo and pushed to the master branch before projects will pick them up.

If you plan to build and deploy linkja-core, it's recommended you clone both of the repositories into the same directory.  For example:

```
/Users/me/Development/
  - linkja/
    - linkja-core/
    - linkja-mvn-repo/
```

After building the JAR, you would deploy it to the local copy of the linkja-mvn-repo repository using the following command:

`mvn deploy`

Finally, you will need to commit the changes made in linkja-mvn-repo, and push the changes to the master branch in GitHub.  Your other projects (e.g., linkja-hashing) should now be able to pull down the new version.

If you are updating an existing version of linkja-core and not bumping the version (discouraged, but just in case...), remember that your local projects will have cached the Maven dependencies.  You will need to force the Maven dependencies to be pulled back down.  From your project, like linkja-hashing, run the following command:

`mvn clean install -U`

## Implementation Details
### Encryption
All crypto goes through the linkja C library ([linkja-crypto](https://github.com/MRAIA-ORG/linkja-crypto)). The [Crypto](src/main/java/org/linkja/core/crypto/Crypto.java) interface lists the calls the linkja programs make: hash, secure hash and its revert, random tokens, keys and IVs, AES encryption, RSA lock and unlock, and the library signature.

- [NativeCrypto](src/main/java/org/linkja/core/crypto/NativeCrypto.java) passes each call to the C library unchanged.
- [FakeCrypto](src/test/java/org/linkja/core/crypto/FakeCrypto.java) is a pure Java copy for tests. It is in the test sources only. Its secure hash uses a test secret, so it differs from the C library. `FakeCryptoTest` shows that the other results agree with the C library.

The C library accepts only 2048-bit RSA keys and uses OAEP padding.

### Exception Handling
Within linkja, the [LinkjaException](src/main/java/org/linkja/core/LinkjaException.java) is intended to be a "safe", user-friendly representation of any particular exception situation.  This means that it should contain intuitive messages with sufficient information for the user to act on.  Any program catching a LinkjaException should be able to catch and display the message to the user.  Please keep this in mind when building and formatting exception messages.