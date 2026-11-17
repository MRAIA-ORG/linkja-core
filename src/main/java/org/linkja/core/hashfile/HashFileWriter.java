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
 * close writes the final row count into the header. A caller whose run fails removes the file itself.
 */
public class HashFileWriter implements Closeable {
  public static final int SESSION_KEY_LENGTH = 32;
  // The C library gives a SHA-256 secure hash as 64 hex characters. An empty hash value is 64 zero bytes.
  private static final int HASH_VALUE_LENGTH = 64;

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
    metadata.write(stream, aggregatorPublicKey, crypto);
  }

  /**
   * Writes one row. plainHashValues holds one plain hash value per hash rule, in HashRule order. A null or empty value
   * is written as an empty hash value.
   */
  public void writeRow(String[] plainHashValues) throws IOException {
    if (plainHashValues.length != HashRule.values().length) {
      throw new IllegalArgumentException(String.format("A row needs %d hash values, but has %d",
        HashRule.values().length, plainHashValues.length));
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
