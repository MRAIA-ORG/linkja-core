package org.linkja.core.hashfile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.linkja.core.crypto.FakeCrypto;
import org.linkja.crypto.RsaResult;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Shows that HashFileWriter writes the same bytes as linkja-hashing 1.1.1 (ADR 0001). The reference file, its input
 * and the steps that made it are in src/test/resources/hashfile-v1 (see the README there).
 */
class HashFileWriterTest {
  private static final String SITE_ID = "1";
  private static final String PROJECT_ID = "Linkja Project";

  /**
   * FakeCrypto with the two changes the reference run made to the C library: a fixed session key (byte i is i) and a
   * predictable RSA lock ("LOCKED(" + data + ")"). Its secure hash and signature equal those of the reference build.
   */
  static class ReferenceCrypto extends FakeCrypto {
    @Override
    public byte[] generateKey(int length) {
      byte[] key = new byte[length];
      for (int index = 0; index < length; index++) {
        key[index] = (byte) index;
      }
      return key;
    }

    @Override
    public RsaResult rsaEncrypt(byte[] data, byte[] key) {
      byte[] start = "LOCKED(".getBytes(StandardCharsets.US_ASCII);
      byte[] locked = new byte[start.length + data.length + 1];
      System.arraycopy(start, 0, locked, 0, start.length);
      System.arraycopy(data, 0, locked, start.length, data.length);
      locked[locked.length - 1] = (byte) ')';
      RsaResult result = new RsaResult();
      result.data = locked;
      result.length = locked.length;
      return result;
    }
  }

  private static HashRule ruleNamed(String ruleName) {
    return Arrays.stream(HashRule.values()).filter(rule -> rule.ruleName().equals(ruleName)).findFirst().orElseThrow();
  }

  private static Path resource(String name) throws Exception {
    return Path.of(HashFileWriterTest.class.getClassLoader().getResource(name).toURI());
  }

  @Test
  void write_givesTheBytesOfTheV1ReferenceFile(@TempDir Path folder) throws Exception {
    Path output = folder.resolve("hashes.enc");
    List<String> rows = Files.readAllLines(resource("hashfile-v1/plain-hash-values.csv"), StandardCharsets.US_ASCII);
    File publicKey = resource("public-test.key").toFile();

    // The first line names the rule of each column. Each value goes to the position of its rule in HashRule.
    String[] ruleNames = rows.get(0).split(",");
    try (HashFileWriter writer = new HashFileWriter(output, SITE_ID, PROJECT_ID, publicKey, new ReferenceCrypto())) {
      for (String row : rows.subList(1, rows.size())) {
        String[] columns = row.split(",", -1);
        String[] values = new String[HashRule.values().length];
        for (int column = 0; column < columns.length; column++) {
          values[ruleNamed(ruleNames[column]).ordinal()] = columns[column];
        }
        writer.writeRow(values);
      }
    }

    assertArrayEquals(Files.readAllBytes(resource("hashfile-v1/reference.enc")), Files.readAllBytes(output));
  }

  @Test
  void hashRules_areTheElevenRulesInFileOrder() {
    assertEquals(List.of("PIDHASH", "fnamelnamedobssn", "lnamefnamedobssn", "fnamelnamedob", "lnamefnamedob",
        "fnamelnameTdobssn", "fnamelnameTdob", "fname3lnamedobssn", "fname3lnamedob", "fnamelnamedobDssn",
        "fnamelnamedobYssn"),
      Arrays.stream(HashRule.values()).map(HashRule::ruleName).toList());
    assertEquals(List.of(false, true, true, false, false, true, false, true, false, true, true),
      Arrays.stream(HashRule.values()).map(HashRule::needsSsn).toList());
  }

  @Test
  void writeRow_rejectsARowWithoutElevenValues(@TempDir Path folder) throws Exception {
    File publicKey = resource("public-test.key").toFile();
    try (HashFileWriter writer = new HashFileWriter(folder.resolve("hashes.enc"), SITE_ID, PROJECT_ID, publicKey,
      new ReferenceCrypto())) {
      assertThrows(IllegalArgumentException.class, () -> writer.writeRow(new String[10]));
    }
  }

  /** Writes the given rows to a new file in folder and gives the file length. */
  private static long writtenLength(Path folder, String name, String[]... rows) throws Exception {
    Path output = folder.resolve(name);
    try (HashFileWriter writer = new HashFileWriter(output, SITE_ID, PROJECT_ID, resource("public-test.key").toFile(),
      new ReferenceCrypto())) {
      for (String[] row : rows) {
        writer.writeRow(row);
      }
    }
    return Files.size(output);
  }

  @ParameterizedTest
  @NullAndEmptySource
  void writeRow_rejectsAnEmptyPidhashWritesNothingForThatRowAndLetsTheCallerContinue(String pidhash, @TempDir Path folder)
    throws Exception {
    String[] row = new String[HashRule.values().length];
    Arrays.fill(row, "A");
    row[HashRule.PIDHASH.ordinal()] = pidhash;
    String[] validRow = new String[HashRule.values().length];
    Arrays.fill(validRow, "B");
    Path output = folder.resolve("hashes.enc");
    try (HashFileWriter writer = new HashFileWriter(output, SITE_ID, PROJECT_ID, resource("public-test.key").toFile(),
      new ReferenceCrypto())) {
      IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> writer.writeRow(row));
      assertTrue(error.getMessage().contains("PIDHASH"), error.getMessage());
      writer.writeRow(validRow);
    }
    writtenLength(folder, "valid-row-only.enc", validRow);
    assertArrayEquals(Files.readAllBytes(folder.resolve("valid-row-only.enc")), Files.readAllBytes(output));
  }

  @Test
  void writeRow_writesANullValueThatIsNotPidhashAs64ZeroBytes(@TempDir Path folder) throws Exception {
    String[] row = new String[HashRule.values().length];
    row[HashRule.PIDHASH.ordinal()] = "A";
    Path output = folder.resolve("hashes.enc");
    try (HashFileWriter writer = new HashFileWriter(output, SITE_ID, PROJECT_ID, resource("public-test.key").toFile(),
      new ReferenceCrypto())) {
      writer.writeRow(row);
    }
    byte[] bytes = Files.readAllBytes(output);
    int rowStart = (int) writtenLength(folder, "no-rows.enc");
    int hashLength = 64;
    assertEquals(rowStart + HashRule.values().length * hashLength, bytes.length);
    byte[] afterPidhash = Arrays.copyOfRange(bytes, rowStart + hashLength, bytes.length);
    assertArrayEquals(new byte[afterPidhash.length], afterPidhash);
  }
}
