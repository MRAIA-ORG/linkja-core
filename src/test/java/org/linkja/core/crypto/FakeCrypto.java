package org.linkja.core.crypto;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.linkja.crypto.AesResult;
import org.linkja.crypto.RsaResult;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Pure Java Crypto for tests. It repeats the C library steps (see linkja-crypto src/linkja-crypto.c), so
 * FakeCryptoTest can show both give the same results.
 *
 * Differences from the C library:
 * - createSecureHash uses FAKE_SECRET in place of the secret built into the C library, so its output differs.
 *   revertSecureHash does not use the secret, so it matches.
 * - getLibrarySignature returns a fixed text.
 * - Strings go in as standard UTF-8. The C library reads modified UTF-8, which differs only for the NUL character
 *   and characters outside the Basic Multilingual Plane.
 * - It does not copy the C library length checks (e.g. AES key must be 32 bytes, RSA key must be 2048 bits).
 */
public class FakeCrypto implements Crypto {
  // Package-private so FakeCryptoTest can check createSecureHash.
  static final byte[] FAKE_SECRET = "linkja-core FakeCrypto test secret".getBytes(StandardCharsets.US_ASCII);
  private static final String SIGNATURE = "(FakeCrypto)";
  private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
  private static final int AES_TAG_BITS = 128;
  // OpenSSL RSA_PKCS1_OAEP_PADDING uses SHA-1 and MGF1 with SHA-1.
  private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
  private static final int HASH_HEX_LENGTH = 64;

  private final SecureRandom random = new SecureRandom();
  private final HexFormat hex = HexFormat.of();

  @Override
  public String hash(String input) {
    return hex.formatHex(sha256(utf8(input)));
  }

  @Override
  public String createSecureHash(String input, byte[] sessionKey, String rowId, String tokenId) {
    byte[] inputHash = sha256(FAKE_SECRET, utf8(input));
    return hex.formatHex(xor(inputHash, supplementalHash(sessionKey, rowId, tokenId)));
  }

  @Override
  public String revertSecureHash(String input, byte[] sessionKey, String rowId, String tokenId) {
    if (input == null || input.length() != HASH_HEX_LENGTH || !input.chars().allMatch(HexFormat::isHexDigit)) {
      throw new IllegalArgumentException("revertSecureHash input must be exactly " + HASH_HEX_LENGTH + " hex characters");
    }
    return hex.formatHex(xor(hex.parseHex(input), supplementalHash(sessionKey, rowId, tokenId)));
  }

  @Override
  public String generateToken(int length) {
    return hex.formatHex(randomBytes(length));
  }

  @Override
  public byte[] generateKey(int length) {
    return randomBytes(length);
  }

  @Override
  public byte[] generateIV(int length) {
    return randomBytes(length);
  }

  @Override
  public String getLibrarySignature() {
    return SIGNATURE;
  }

  @Override
  public AesResult aesEncrypt(byte[] data, byte[] aad, byte[] key, byte[] iv) {
    try {
      Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(AES_TAG_BITS, iv));
      cipher.updateAAD(aad);
      byte[] output = cipher.doFinal(data);
      // Java puts the tag after the data. The C library returns them apart.
      int dataLength = output.length - AES_TAG_BITS / 8;
      AesResult result = new AesResult();
      result.data = Arrays.copyOfRange(output, 0, dataLength);
      result.tag = Arrays.copyOfRange(output, dataLength, output.length);
      return result;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public RsaResult rsaEncrypt(byte[] data, byte[] key) {
    return rsa(Cipher.ENCRYPT_MODE, data, key);
  }

  @Override
  public RsaResult rsaDecrypt(byte[] data, byte[] key) {
    return rsa(Cipher.DECRYPT_MODE, data, key);
  }

  private RsaResult rsa(int mode, byte[] data, byte[] pemKey) {
    try {
      Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
      cipher.init(mode, readPemKey(pemKey));
      RsaResult result = new RsaResult();
      result.data = cipher.doFinal(data);
      result.length = result.data.length;
      return result;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  // Reads a PEM public key, or a PEM private key in PKCS#1 or PKCS#8 form, as the C library does.
  private static Key readPemKey(byte[] pemKey) throws Exception {
    try (PEMParser parser = new PEMParser(new StringReader(new String(pemKey, StandardCharsets.US_ASCII)))) {
      Object parsed = parser.readObject();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
      return switch (parsed) {
        case SubjectPublicKeyInfo info -> converter.getPublicKey(info);
        case PEMKeyPair pair -> converter.getPrivateKey(pair.getPrivateKeyInfo());
        case PrivateKeyInfo info -> converter.getPrivateKey(info);
        default -> throw new IllegalArgumentException("Not a PEM RSA key");
      };
    }
  }

  // SHA-256 of session key, row ID and token ID, in that order, as in hash_supplemental_data.
  private static byte[] supplementalHash(byte[] sessionKey, String rowId, String tokenId) {
    return sha256(sessionKey, utf8(rowId), utf8(tokenId));
  }

  private static byte[] sha256(byte[]... parts) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (byte[] part : parts) {
        digest.update(part);
      }
      return digest.digest();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] xor(byte[] a, byte[] b) {
    byte[] output = new byte[a.length];
    for (int index = 0; index < a.length; index++) {
      output[index] = (byte) (a[index] ^ b[index]);
    }
    return output;
  }

  private static byte[] utf8(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private byte[] randomBytes(int length) {
    byte[] output = new byte[length];
    random.nextBytes(output);
    return output;
  }
}
