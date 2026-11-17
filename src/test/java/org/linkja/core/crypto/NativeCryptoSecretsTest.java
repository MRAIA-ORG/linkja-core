package org.linkja.core.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Checks NativeCrypto.createSecureHash against the C library. Only a linkja-crypto build with INCLUDE_SECRETS=ON has
 * createSecureHash. The public build throws UnsupportedOperationException, and then these tests are skipped.
 *
 * The test cannot know the secret, so it checks that the revert of a secure hash does not depend on the session
 * key, row ID or token ID that made it.
 */
class NativeCryptoSecretsTest {
  private static final Crypto real = new NativeCrypto();

  @BeforeAll
  static void needsSecretsBuild() {
    boolean secretsBuild = true;
    try {
      real.createSecureHash("probe", new byte[] { 1 }, "1", "T");
    } catch (UnsupportedOperationException e) {
      secretsBuild = false;
    }
    assumeTrue(secretsBuild, "Skipped: the linkja-crypto library is a public build without secrets, so "
      + "createSecureHash throws. Build it with INCLUDE_SECRETS=ON to run this test.");
  }

  @Test
  void createSecureHash_revertsToTheSameValueForAnySessionKeyRowAndToken() {
    String input = real.hash("test");
    byte[] keyA = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    byte[] keyB = "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.US_ASCII);

    String secureA = real.createSecureHash(input, keyA, "1001", "PIDHASH");
    String secureB = real.createSecureHash(input, keyB, "2002", "FNAMEHASH");
    assertNotEquals(secureA, secureB);

    String revertedA = real.revertSecureHash(secureA, keyA, "1001", "PIDHASH");
    String revertedB = real.revertSecureHash(secureB, keyB, "2002", "FNAMEHASH");
    assertEquals(64, revertedA.length());
    assertEquals(revertedA, revertedB);
    assertNotEquals(input, revertedA);
  }
}
