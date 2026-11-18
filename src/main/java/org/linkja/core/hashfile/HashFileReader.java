package org.linkja.core.hashfile;

import org.linkja.core.EncryptedHashFileMetadata;
import org.linkja.core.LinkjaException;
import org.linkja.core.crypto.Crypto;

import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Reads a v1 hash file, as HashFileWriter and linkja-hashing 1.1.1 write it (ADR 0001).
 *
 * The constructor reads the header and the envelope, and unlocks the session key with the RSA private key. A bad or
 * truncated header throws LinkjaException with a message that names the part that is wrong. readRow gives the values
 * of one row, in the order of the header's hash columns (HashRule order for a v1 file): each secure hash with the
 * session key, row ID and token ID taken out again, in upper case, and "" for an empty value (64 zero bytes).
 */
public class HashFileReader implements Closeable {
  // The C library gives a SHA-256 secure hash as 64 hex characters. An empty hash value is 64 zero bytes.
  private static final int HASH_VALUE_LENGTH = 64;

  private final Crypto crypto;
  private final BufferedInputStream stream;
  private final EncryptedHashFileMetadata metadata;
  private long numRows = 0;

  public HashFileReader(Path path, File rsaPrivateKey, Crypto crypto) throws IOException, LinkjaException {
    this.crypto = crypto;
    this.stream = new BufferedInputStream(Files.newInputStream(path));
    try {
      this.metadata = EncryptedHashFileMetadata.read(stream, rsaPrivateKey, crypto);
    } catch (IOException | LinkjaException | RuntimeException e) {
      stream.close();
      throw e;
    }
  }

  /** The header of the file: site ID, project ID, number of hash columns and rows, and the session key. */
  public EncryptedHashFileMetadata metadata() {
    return metadata;
  }

  /**
   * Gives the values of the next row, or null after the last row. Throws LinkjaException when the file ends before
   * the number of rows its header gives, or has more data after them.
   */
  public String[] readRow() throws IOException, LinkjaException {
    if (numRows == metadata.getNumHashRows()) {
      if (stream.read() != -1) {
        throw new LinkjaException(String.format("The hash file has more data after its %d rows", numRows));
      }
      return null;
    }
    numRows++;
    String rowId = Long.toString(numRows);
    String[] values = new String[metadata.getNumHashColumns()];
    for (int column = 0; column < values.length; column++) {
      byte[] data = stream.readNBytes(HASH_VALUE_LENGTH);
      if (data.length != HASH_VALUE_LENGTH) {
        throw new LinkjaException(String.format("The hash file ends in row %d, but its header says it has %d rows",
          numRows, metadata.getNumHashRows()));
      }
      // A hex character is never a zero byte, so a zero first byte marks an empty value (as linkja-matching reads it).
      values[column] = data[0] == 0 ? "" : crypto.revertSecureHash(new String(data, StandardCharsets.US_ASCII),
        metadata.getSessionKey(), rowId, Integer.toString(column + 1)).toUpperCase();
    }
    return values;
  }

  @Override
  public void close() throws IOException {
    stream.close();
  }
}
