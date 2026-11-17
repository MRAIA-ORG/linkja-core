package org.linkja.core.hashfile;

/**
 * The 11 hash rules, declared in the order their hash values appear in each row of a v1 hash file. The token ID of a
 * rule in the secure hash is its position, starting at 1 (see tokenId).
 *
 * The order is the one linkja-hashing 1.1.1 writes (Engine.writeDataRowResult), which differs from the order of
 * HashingStep.HASH_FIELDS there. Do not reorder: ADR 0001 keeps v1 files byte-identical.
 */
public enum HashRule {
  PIDHASH("PIDHASH", false),
  FNAMELNAMEDOBSSN("fnamelnamedobssn", true),
  LNAMEFNAMEDOBSSN("lnamefnamedobssn", true),
  FNAMELNAMEDOB("fnamelnamedob", false),
  LNAMEFNAMEDOB("lnamefnamedob", false),
  FNAMELNAMETDOBSSN("fnamelnameTdobssn", true),
  FNAMELNAMETDOB("fnamelnameTdob", false),
  FNAME3LNAMEDOBSSN("fname3lnamedobssn", true),
  FNAME3LNAMEDOB("fname3lnamedob", false),
  FNAMELNAMEDOBDSSN("fnamelnamedobDssn", true),
  FNAMELNAMEDOBYSSN("fnamelnamedobYssn", true);

  private final String ruleName;
  private final boolean needsSsn;

  HashRule(String ruleName, boolean needsSsn) {
    this.ruleName = ruleName;
    this.needsSsn = needsSsn;
  }

  /** The rule name linkja-hashing uses for this rule, e.g. "fnamelnamedob". */
  public String ruleName() {
    return ruleName;
  }

  /** True when the rule mixes in the SSN, so its hash value is empty for a row without one. */
  public boolean needsSsn() {
    return needsSsn;
  }

  /** The token ID of this rule in the secure hash: its position in the row, starting at 1. */
  public String tokenId() {
    return Integer.toString(ordinal() + 1);
  }
}
