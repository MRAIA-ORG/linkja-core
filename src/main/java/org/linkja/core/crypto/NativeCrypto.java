package org.linkja.core.crypto;

import org.linkja.crypto.AesResult;
import org.linkja.crypto.Library;
import org.linkja.crypto.RsaResult;

/**
 * Crypto backed by the linkja C library. Each method passes its inputs unchanged to the Library call of the same
 * name and returns that call's result unchanged.
 */
public class NativeCrypto implements Crypto {
  @Override
  public String hash(String input) {
    return Library.hash(input);
  }

  @Override
  public String createSecureHash(String input, byte[] sessionKey, String rowId, String tokenId) {
    return Library.createSecureHash(input, sessionKey, rowId, tokenId);
  }

  @Override
  public String revertSecureHash(String input, byte[] sessionKey, String rowId, String tokenId) {
    return Library.revertSecureHash(input, sessionKey, rowId, tokenId);
  }

  @Override
  public String generateToken(int length) {
    return Library.generateToken(length);
  }

  @Override
  public byte[] generateKey(int length) {
    return Library.generateKey(length);
  }

  @Override
  public byte[] generateIV(int length) {
    return Library.generateIV(length);
  }

  @Override
  public String getLibrarySignature() {
    return Library.getLibrarySignature();
  }

  @Override
  public AesResult aesEncrypt(byte[] data, byte[] aad, byte[] key, byte[] iv) {
    return Library.aesEncrypt(data, aad, key, iv);
  }

  @Override
  public RsaResult rsaEncrypt(byte[] data, byte[] key) {
    return Library.rsaEncrypt(data, key);
  }

  @Override
  public RsaResult rsaDecrypt(byte[] data, byte[] key) {
    return Library.rsaDecrypt(data, key);
  }
}
