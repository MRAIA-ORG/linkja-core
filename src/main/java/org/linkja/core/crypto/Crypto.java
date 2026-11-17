package org.linkja.core.crypto;

import org.linkja.crypto.AesResult;
import org.linkja.crypto.RsaResult;

/**
 * The crypto calls the linkja programs make. Each method has the same name, inputs and result as the
 * org.linkja.crypto.Library call it stands for.
 *
 * NativeCrypto calls the C library. Tests can use a pure Java fake (FakeCrypto, in the test sources), so code that
 * takes a Crypto can be tested without the C library.
 *
 * The list holds only calls that src/main of linkja-core, linkja-hashing, linkja-matching and linkja-salt-engine
 * make. Library.aesDecrypt is left out because no program calls it.
 */
public interface Crypto {
  String hash(String input);

  String createSecureHash(String input, byte[] sessionKey, String rowId, String tokenId);

  String revertSecureHash(String input, byte[] sessionKey, String rowId, String tokenId);

  String generateToken(int length);

  byte[] generateKey(int length);

  byte[] generateIV(int length);

  String getLibrarySignature();

  AesResult aesEncrypt(byte[] data, byte[] aad, byte[] key, byte[] iv);

  RsaResult rsaEncrypt(byte[] data, byte[] key);

  RsaResult rsaDecrypt(byte[] data, byte[] key);
}
