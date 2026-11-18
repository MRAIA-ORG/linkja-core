package org.linkja.core.hashfile;

import org.linkja.core.EncryptedHashFileMetadata;
import org.linkja.core.LinkjaException;
import org.linkja.core.crypto.Crypto;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Writes a v1 hash file, byte for byte the same as linkja-hashing 1.1.1 (ADR 0001).
 *
 * The constructor makes a new file (it fails if the file is there), a random session key, and writes the header with a
 * row count of 0 and the envelope. writeRow writes the secure hash of each of the 11 plain hash values of one row.
 * An empty or null PIDHASH stops writeRow with an error, because a v1 file never has a row without one. Any other
 * empty or null value is written as 64 zero bytes, the same as linkja-hashing 1.1.1.
 * close writes the final row count into the header. A caller whose run fails removes the file itself.
 */
public class HashFileWriter implements Closeable {
  public static final int SESSION_KEY_LENGTH = 32;
  // The C library gives a SHA-256 secure hash as 64 hex characters. An empty hash value is 64 zero bytes.
  static final int HASH_VALUE_LENGTH = 64;

  private final Path path;
  private final Crypto crypto;
  private final byte[] sessionKey;
  private final EncryptedHashFileMetadata metadata;
  private final BufferedOutputStream stream;
  private long numRows = 0;

  public HashFileWriter(Path path, String siteId, String projectId, File aggregatorPublicKey, Crypto crypto)
    throws IOException, LinkjaException {
    this.path = path;
    this.crypto = crypto;
    this.sessionKey = crypto.generateKey(SESSION_KEY_LENGTH);
    this.metadata = new EncryptedHashFileMetadata(siteId, projectId, HashRule.values().length, 0, sessionKey,
      crypto.getLibrarySignature());
    this.stream = new BufferedOutputStream(Files.newOutputStream(path, StandardOpenOption.CREATE_NEW,
      StandardOpenOption.WRITE));
    try {
      metadata.write(stream, aggregatorPublicKey, crypto);
    } catch (Throwable e) {
      closeAfterFailure(stream, e);
      throw e;
    }
  }

  /**
   * Writes one row. plainHashValues holds one plain hash value per hash rule, in HashRule order. A null or empty
   * PIDHASH throws IllegalArgumentException, and nothing is written for that row. Any other null or empty value is
   * written as 64 zero bytes.
   */
  public void writeRow(String[] plainHashValues) throws IOException {
    if (plainHashValues.length != HashRule.values().length) {
      throw new IllegalArgumentException(String.format("A row needs %d hash values, but has %d",
        HashRule.values().length, plainHashValues.length));
    }
    String pidhash = plainHashValues[HashRule.PIDHASH.ordinal()];
    if (pidhash == null || pidhash.isEmpty()) {
      throw new IllegalArgumentException("A row needs a PIDHASH value, but it is empty");
    }
    numRows++;
    String rowId = Long.toString(numRows);
    for (HashRule rule : HashRule.values()) {
      String value = plainHashValues[rule.ordinal()];
      if (value == null || value.isEmpty()) {
        stream.write(new byte[HASH_VALUE_LENGTH]);
      } else {
        String secureHash = crypto.createSecureHash(value, sessionKey, rowId, rule.tokenId()).toUpperCase();
        stream.write(secureHash.getBytes(StandardCharsets.US_ASCII));
      }
    }
  }

  /** Closes stream after failure, the error that stops a constructor. An error from close is added to failure. */
  static void closeAfterFailure(Closeable stream, Throwable failure) {
    try {
      stream.close();
    } catch (Throwable closeError) {
      failure.addSuppressed(closeError);
    }
  }

  /** Closes the file and writes the final row count into its header. */
  @Override
  public void close() throws IOException {
    stream.close();
    metadata.setNumHashRows(numRows);
    try {
      metadata.writeUpdatedNumHashRows(path.toFile());
    } catch (LinkjaException e) {
      throw new IOException(e);
    }
  }
}
