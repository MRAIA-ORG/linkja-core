# v1 reference hash file

`HashFileWriterTest` checks that `HashFileWriter` writes the same bytes as `reference.enc`. Unchanged linkja-hashing code made that file (ADR 0001 in linkja-workspace).

## Files

- `reference.enc`: the hash file that linkja-hashing wrote. It has 20 rows: 5 rows with an SSN and 15 rows without one. One more input row is invalid, so the file leaves it out.
- `plain-hash-values.csv`: the input of the test. The first line names the hash rule of each column, in the order linkja-hashing writes them (`Engine.writeDataRowResult`, token IDs 1 to 11). Then one line per row of `reference.enc`, in the same order. A value is empty where linkja-hashing wrote an empty hash value. The test places each value by its rule name, so a change to the order of `HashRule` changes the bytes the test writes.
- `input.csv`: the input extract of the run. It holds rows 1 to 20 of `src/main/resources/example/test_data.csv` in linkja-hashing, plus one row with no last name.
- `linkja-crypto-reference.patch`: the change to the C library for the run.

## What the run changed, and why

The hash file has a random session key and random RSA padding. A real run therefore never gives the same bytes twice. The run used linkja-hashing and linkja-core 1.1.0 as they are. It changed only the C library (`linkja-crypto-reference.patch`):

- `generateKey` gives a fixed key: byte i is i.
- `rsaEncrypt` gives `LOCKED(` + data + `)` in place of RSA with OAEP padding.
- `createSecureHash` also writes its row ID, token ID and plain input to the file in `LINKJA_REFERENCE_LOG`. That log gives `plain-hash-values.csv`.

The library secret is the bytes of `FakeCrypto.FAKE_SECRET`, and the library signature is `(FakeCrypto)`. So `FakeCrypto` gives the same secure hash and signature as this build. The test therefore needs no C library. Its `ReferenceCrypto` adds the same fixed key and `LOCKED(...)` step.

The input stays within one batch (1000 rows), so the row order is fixed. The site ID (`1`) and project ID (`Linkja Project`) are ASCII, so the bytes do not depend on the platform charset.

## Make it again

You need Java 25, Maven, OpenSSL 3, CMake and git (e.g. `brew install openjdk@25 maven openssl@3 cmake`). Run this from the linkja-core folder:

```
CORE="$PWD"
REF="$CORE/src/test/resources/hashfile-v1"
WORK="$(mktemp -d)"
export JAVA_HOME="$(brew --prefix openjdk@25)/libexec/openjdk.jdk/Contents/Home"
cd "$WORK"

# The C library at linkja-crypto develop, with the patch and the FakeCrypto secret.
git clone -q https://github.com/MRAIA-ORG/linkja-crypto crypto
git -C crypto checkout -q 7195f36551e0e6cb9d82221752a64b88fe10e8aa
git -C crypto apply "$REF/linkja-crypto-reference.patch"
python3 -c "
b = b'linkja-core FakeCrypto test secret'
print('#ifndef LINKJA_SECRET_H\n#define LINKJA_SECRET_H\n#define LINKJA_SECRET_LEN %d\n#define LINKJA_SECRET {%s}\n#define LINKJA_SECRET_HASH \"(FakeCrypto)\"\n#endif'
      % (len(b), ', '.join('0x%02x' % x for x in b)))" > crypto/src/include/linkja_secret.h
(cd crypto && cmake . -DINCLUDE_SECRETS=ON -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" > /dev/null && make linkjacrypto > /dev/null)

# linkja-hashing at develop, unchanged. It gets linkja-core 1.1.0 from linkja-mvn-repo.
git clone -q https://github.com/MRAIA-ORG/linkja-hashing hashing
git -C hashing checkout -q a36b01987cb2ca2fff9c30b3b559c5fae58882ad
(cd hashing && mvn -q clean package -DskipTests)

# The run.
mkdir out
EXAMPLE=hashing/src/main/resources/example
LINKJA_REFERENCE_LOG="$WORK/plain.log" "$JAVA_HOME/bin/java" -Djava.library.path=crypto/target \
  --enable-native-access=ALL-UNNAMED -jar hashing/target/Hashing-1.1.1-jar-with-dependencies.jar \
  --encryptionKey "$EXAMPLE/public-test.key" --saltFile "$EXAMPLE/unencrypted_salt.txt" \
  --patientFile "$REF/input.csv" --privateDate 01/01/2018 --outDirectory out > /dev/null

# The log as a line of rule names, then one line of 11 values per row.
python3 -c "
print('PIDHASH,fnamelnamedobssn,lnamefnamedobssn,fnamelnamedob,lnamefnamedob,fnamelnameTdobssn,fnamelnameTdob,fname3lnamedobssn,fname3lnamedob,fnamelnamedobDssn,fnamelnamedobYssn')
rows = {}
for line in open('plain.log'):
    row, token, value = line.strip().split(',')
    rows.setdefault(int(row), {})[int(token)] = value
for row in sorted(rows):
    print(','.join(rows[row].get(token, '') for token in range(1, 12)))" > plain-hash-values.csv

cmp out/hashes_*.enc "$REF/reference.enc" && cmp plain-hash-values.csv "$REF/plain-hash-values.csv" && echo SAME
```

The last line prints `SAME` when the run gives the committed files again.
