package org.linkja.core.crypto;

import org.junit.jupiter.api.Test;
import org.linkja.crypto.AesResult;
import org.linkja.crypto.RsaResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Shows that FakeCrypto (pure Java) gives the same results as NativeCrypto (the C library) for each operation the
 * fake can match. createSecureHash is the exception: the C library mixes in a secret the fake does not have, so the
 * test shows instead that the C library reverts a fake secure hash the same way the fake does.
 * getLibrarySignature names the C library build, so the fake has nothing to match.
 *
 * Two tests do not compare the two. Random values cannot match, so each side is checked alone for length and
 * format. The fake's secure hash is checked alone against sha256 of its own secret and the input.
 */
class FakeCryptoTest {
  private final Crypto fake = new FakeCrypto();
  private final Crypto real = new NativeCrypto();

  private static byte[] resource(String name) throws Exception {
    return Files.readAllBytes(Path.of(FakeCryptoTest.class.getClassLoader().getResource(name).toURI()));
  }

  @Test
  void hash_agrees() {
    for (String input : new String[] { "", "test", "JOSE1980-01-01", "José Åström" }) {
      assertEquals(real.hash(input), fake.hash(input), input);
    }
  }

  @Test
  void secureHash_revertAgrees() {
    byte[] sessionKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    String secureHash = fake.createSecureHash(fake.hash("test"), sessionKey, "1001", "PIDHASH");
    assertEquals(64, secureHash.length());
    assertEquals(real.revertSecureHash(secureHash, sessionKey, "1001", "PIDHASH"),
      fake.revertSecureHash(secureHash, sessionKey, "1001", "PIDHASH"));
    String upperCase = secureHash.toUpperCase();
    assertEquals(real.revertSecureHash(upperCase, sessionKey, "1001", "PIDHASH"),
      fake.revertSecureHash(upperCase, sessionKey, "1001", "PIDHASH"));
  }

  @Test
  void secureHash_revertRejectsBadInputLikeTheCLibrary() {
    byte[] sessionKey = new byte[] { 1, 2, 3 };
    assertThrows(IllegalArgumentException.class, () -> real.revertSecureHash("abc", sessionKey, "1", "T"));
    assertThrows(IllegalArgumentException.class, () -> fake.revertSecureHash("abc", sessionKey, "1", "T"));
  }

  @Test
  void aesEncrypt_agrees() {
    byte[] data = "a hash value".getBytes(StandardCharsets.US_ASCII);
    byte[] aad = "aad-0123456789ab".getBytes(StandardCharsets.US_ASCII);
    byte[] key = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    byte[] iv = "0123456789ab".getBytes(StandardCharsets.US_ASCII);
    AesResult expected = real.aesEncrypt(data, aad, key, iv);
    AesResult actual = fake.aesEncrypt(data, aad, key, iv);
    assertArrayEquals(expected.data, actual.data);
    assertArrayEquals(expected.tag, actual.tag);
  }

  // RSA with OAEP padding is random, so the two cannot give the same bytes. Each must unlock what the other locks.
  @Test
  void rsa_eachUnlocksWhatTheOtherLocks() throws Exception {
    byte[] publicKey = resource("public-test.key");
    byte[] privateKey = resource("private-test.key");
    byte[] data = "a session key".getBytes(StandardCharsets.US_ASCII);

    RsaResult lockedByFake = fake.rsaEncrypt(data, publicKey);
    RsaResult lockedByReal = real.rsaEncrypt(data, publicKey);
    assertEquals(lockedByReal.length, lockedByFake.length);
    assertEquals(lockedByReal.data.length, lockedByFake.data.length);

    RsaResult unlockedByReal = real.rsaDecrypt(lockedByFake.data, privateKey);
    RsaResult unlockedByFake = fake.rsaDecrypt(lockedByReal.data, privateKey);
    assertArrayEquals(data, unlockedByReal.data);
    assertArrayEquals(data, unlockedByFake.data);
    assertEquals(unlockedByReal.length, unlockedByFake.length);
  }

  // Random output: the two agree on length and format only. Two lengths show the length is used. Two calls that
  // differ show the output is not a constant.
  @Test
  void randomValues_agreeOnLengthAndFormat() {
    for (Crypto crypto : new Crypto[] { real, fake }) {
      String name = crypto.getClass().getSimpleName();
      for (int length : new int[] { 16, 32 }) {
        assertEquals(length, crypto.generateKey(length).length, name);
        assertEquals(length, crypto.generateIV(length).length, name);
        String token = crypto.generateToken(length);
        assertTrue(token.matches("[0-9a-f]{" + 2 * length + "}"), name + ": " + token);
      }
      assertFalse(Arrays.equals(crypto.generateKey(16), crypto.generateKey(16)), name);
      assertFalse(Arrays.equals(crypto.generateIV(16), crypto.generateIV(16)), name);
      assertNotEquals(crypto.generateToken(16), crypto.generateToken(16), name);
    }
  }

  // The fake's secure hash, reverted, must be the hex of sha256(FAKE_SECRET + input), as in the C library with its
  // own secret. Row ID and token ID differ, so a swap of the two is caught.
  @Test
  void fakeSecureHash_revertGivesSecretHashOfInput() throws Exception {
    byte[] sessionKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    String input = fake.hash("test");
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(FakeCrypto.FAKE_SECRET);
    String expected = HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));

    String secureHash = fake.createSecureHash(input, sessionKey, "1001", "PIDHASH");
    assertNotEquals(expected, secureHash);
    assertEquals(expected, fake.revertSecureHash(secureHash, sessionKey, "1001", "PIDHASH"));
  }
}
