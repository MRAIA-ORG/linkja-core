package org.linkja.core.hashfile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.linkja.core.EncryptedHashFileMetadata;
import org.linkja.core.LinkjaException;
import org.linkja.core.crypto.Crypto;
import org.linkja.core.crypto.FakeCrypto;
import org.linkja.crypto.RsaResult;

import java.io.BufferedOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.linkja.core.hashfile.HashFileWriterTest.ReferenceCrypto;
import static org.linkja.core.hashfile.HashFileWriterTest.openFileCount;
import static org.linkja.core.hashfile.HashFileWriterTest.resource;
import static org.linkja.core.hashfile.HashFileWriterTest.writeHashFile;

/** Shows that HashFileReader reads what HashFileWriter writes, including the v1 reference file. */
class HashFileReaderTest {
  private static final Crypto FAKE_CRYPTO = new FakeCrypto();
  private static final byte[] OTHER_SESSION_KEY = new byte[HashFileWriter.SESSION_KEY_LENGTH];

  /**
   * The value the reader gives for a plain hash value: the secure hash with the session key, row ID and token ID taken
   * out again. It does not depend on them, so this uses another session key, row ID and token ID than the file.
   */
  private static String readValueOf(String plainHashValue) {
    if (plainHashValue == null || plainHashValue.isEmpty()) {
      return "";
    }
    String secureHash = FAKE_CRYPTO.createSecureHash(plainHashValue, OTHER_SESSION_KEY, "99", "99");
    return FAKE_CRYPTO.revertSecureHash(secureHash, OTHER_SESSION_KEY, "99", "99").toUpperCase();
  }

  private static File privateKey() throws Exception {
    return resource("private-test.key").toFile();
  }

  private static String[] row(String value) {
    String[] row = new String[HashRule.values().length];
    Arrays.fill(row, value);
    return row;
  }

  @Test
  void read_givesTheValuesOfTheV1ReferenceFile() throws Exception {
    List<String> rows = Files.readAllLines(resource("hashfile-v1/plain-hash-values.csv"), StandardCharsets.US_ASCII);
    try (HashFileReader reader = new HashFileReader(resource("hashfile-v1/reference.enc"), privateKey(),
      new ReferenceCrypto())) {
      EncryptedHashFileMetadata metadata = reader.metadata();
      assertEquals("1", metadata.getSiteId());
      assertEquals("Linkja Project", metadata.getProjectId());
      assertEquals(HashRule.values().length, metadata.getNumHashColumns());
      assertEquals(rows.size() - 1, metadata.getNumHashRows());
      // The columns of plain-hash-values.csv are in HashRule order (HashFileWriterTest checks that order).
      for (String line : rows.subList(1, rows.size())) {
        String[] expected = Arrays.stream(line.split(",", -1)).map(HashFileReaderTest::readValueOf)
          .toArray(String[]::new);
        assertArrayEquals(expected, reader.readRow());
      }
      assertNull(reader.readRow());
    }
  }

  @Test
  void writeThenRead_givesBackEachValueWithRealRsa(@TempDir Path folder) throws Exception {
    String[] first = row("A");
    first[HashRule.FNAMELNAMEDOBSSN.ordinal()] = null;
    first[HashRule.FNAMELNAMEDOBYSSN.ordinal()] = "";
    String[] second = row("B");
    Path output = folder.resolve("hashes.enc");
    try (HashFileWriter writer = new HashFileWriter(output, "site", "project", resource("public-test.key").toFile(),
      FAKE_CRYPTO)) {
      writer.writeRow(first);
      writer.writeRow(second);
    }

    try (HashFileReader reader = new HashFileReader(output, privateKey(), FAKE_CRYPTO)) {
      assertEquals("site", reader.metadata().getSiteId());
      assertEquals("project", reader.metadata().getProjectId());
      assertEquals(2, reader.metadata().getNumHashRows());
      assertArrayEquals(Arrays.stream(first).map(HashFileReaderTest::readValueOf).toArray(), reader.readRow());
      assertArrayEquals(Arrays.stream(second).map(HashFileReaderTest::readValueOf).toArray(), reader.readRow());
      assertNull(reader.readRow());
    }
  }

  /** Writes a file with one row, keeps its first `length` bytes and gives the error message the reader then gives. */
  private static String errorForFirstBytes(Path folder, int length) throws Exception {
    byte[] bytes = Files.readAllBytes(writeHashFile(folder, "hashes.enc", row("A")));
    Path cut = Files.write(folder.resolve("cut.enc"), Arrays.copyOf(bytes, length));
    return assertThrows(LinkjaException.class, () -> new HashFileReader(cut, privateKey(), new ReferenceCrypto()))
      .getMessage();
  }

  @ParameterizedTest
  @CsvSource({
    "0, Invalid metadata start block in header",
    "20, Invalid metadata start block in header",
    "33, Missing or invalid metadata version in header",
    "37, Invalid site ID length in header",
  })
  void constructor_namesTheProblemOfATruncatedHeader(int length, String message, @TempDir Path folder)
    throws Exception {
    assertEquals(message, errorForFirstBytes(folder, length));
  }

  @Test
  void constructor_namesTheProblemOfAHeaderCutInTheEnvelopeEnd(@TempDir Path folder) throws Exception {
    int headerLength = (int) Files.size(writeHashFile(folder, "no-rows.enc"));
    assertEquals("Invalid envelope end block in header", errorForFirstBytes(folder, headerLength - 2));
  }

  @Test
  void constructor_rejectsAFileThatDoesNotStartWithTheHeaderBlock(@TempDir Path folder) throws Exception {
    byte[] bytes = Files.readAllBytes(writeHashFile(folder, "hashes.enc", row("A")));
    bytes[5] = 'X';
    Path changed = Files.write(folder.resolve("changed.enc"), bytes);
    LinkjaException error = assertThrows(LinkjaException.class,
      () -> new HashFileReader(changed, privateKey(), new ReferenceCrypto()));
    assertEquals("Invalid metadata start block in header", error.getMessage());
  }

  @Test
  void constructor_closesTheFileWhenItFails(@TempDir Path folder) throws Exception {
    Path empty = Files.createFile(folder.resolve("empty.enc"));
    long openFiles = openFileCount();
    assertThrows(LinkjaException.class, () -> new HashFileReader(empty, privateKey(), new ReferenceCrypto()));
    assertEquals(openFiles, openFileCount());
  }

  @Test
  void constructor_closesTheFileWhenTheCryptoThrowsAnUncheckedError(@TempDir Path folder) throws Exception {
    Path file = writeHashFile(folder, "hashes.enc", row("A"));
    Crypto failingCrypto = new ReferenceCrypto() {
      @Override
      public RsaResult rsaDecrypt(byte[] data, byte[] key) {
        throw new IllegalStateException("rsaDecrypt failed");
      }
    };
    long openFiles = openFileCount();
    IllegalStateException error = assertThrows(IllegalStateException.class,
      () -> new HashFileReader(file, privateKey(), failingCrypto));
    assertEquals("rsaDecrypt failed", error.getMessage());
    assertEquals(openFiles, openFileCount());
  }

  @Test
  void constructor_closesTheFileWhenTheCryptoThrowsAnError(@TempDir Path folder) throws Exception {
    Path file = writeHashFile(folder, "hashes.enc", row("A"));
    Crypto failingCrypto = new ReferenceCrypto() {
      @Override
      public RsaResult rsaDecrypt(byte[] data, byte[] key) {
        throw new UnsatisfiedLinkError("rsaDecrypt failed");
      }
    };
    long openFiles = openFileCount();
    assertThrows(UnsatisfiedLinkError.class, () -> new HashFileReader(file, privateKey(), failingCrypto));
    assertEquals(openFiles, openFileCount());
  }

  @ParameterizedTest
  @CsvSource({"10", "12", "2147483647"})
  void constructor_rejectsAHeaderWithoutElevenHashColumns(int numHashColumns, @TempDir Path folder) throws Exception {
    Path file = folder.resolve("hashes.enc");
    EncryptedHashFileMetadata metadata = new EncryptedHashFileMetadata("1", "Linkja Project", numHashColumns, 0,
      new byte[HashFileWriter.SESSION_KEY_LENGTH], "signature");
    try (BufferedOutputStream stream = new BufferedOutputStream(Files.newOutputStream(file))) {
      metadata.write(stream, resource("public-test.key").toFile(), new ReferenceCrypto());
    }
    long openFiles = openFileCount();
    LinkjaException error = assertThrows(LinkjaException.class,
      () -> new HashFileReader(file, privateKey(), new ReferenceCrypto()));
    assertEquals(String.format("A v1 hash file has 11 hash columns, but its header says %d", numHashColumns),
      error.getMessage());
    assertEquals(openFiles, openFileCount());
  }

  @ParameterizedTest
  @CsvSource({"1", "64", "704"})
  void readRow_namesTheRowWhereTheFileEnds(int bytesCut, @TempDir Path folder) throws Exception {
    byte[] bytes = Files.readAllBytes(writeHashFile(folder, "hashes.enc", row("A"), row("B")));
    Path cut = Files.write(folder.resolve("cut.enc"), Arrays.copyOf(bytes, bytes.length - bytesCut));
    try (HashFileReader reader = new HashFileReader(cut, privateKey(), new ReferenceCrypto())) {
      reader.readRow();
      LinkjaException error = assertThrows(LinkjaException.class, reader::readRow);
      assertEquals("The hash file ends in row 2, but its header says it has 2 rows", error.getMessage());
    }
  }

  @Test
  void readRow_rejectsDataAfterTheLastRow(@TempDir Path folder) throws Exception {
    byte[] bytes = Files.readAllBytes(writeHashFile(folder, "hashes.enc", row("A")));
    Path longer = Files.write(folder.resolve("longer.enc"), Arrays.copyOf(bytes, bytes.length + 1));
    try (HashFileReader reader = new HashFileReader(longer, privateKey(), new ReferenceCrypto())) {
      reader.readRow();
      LinkjaException error = assertThrows(LinkjaException.class, reader::readRow);
      assertEquals("The hash file has more data after its 1 rows", error.getMessage());
    }
  }
}
