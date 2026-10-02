# Independent PKCS11 smoke consumer

This original Apache-2.0 C application loads an arbitrary compatible native
PKCS11 module, selects one token, signs a fixed message with P256 ECDSA, and
exports public artifacts. A separate Python standard-library script invokes
OpenSSL for independent positive and negative verification. Neither program
uses `pkcs11-check`. Build and run these tools in the application environment;
they do not belong in a basic provider runtime image.

## Build

Linux (C11 compiler and libc development headers):

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic smoke.c p256.c -ldl -o p11lab-smoke
```

Native Windows, in a Visual Studio Developer Command Prompt with a current MSVC
C11 compiler:

```bat
cl /nologo /std:c11 /W4 /WX /O2 /D_CRT_SECURE_NO_WARNINGS smoke.c p256.c /Fe:p11lab-smoke.exe
```

Use the same architecture as the module: a 64-bit application needs a 64-bit
module. Windows uses its native `unsigned long` and packed PKCS11 structures;
Linux uses its native ABI. The pinned, unmodified header supplies these platform
conventions. Windows module/file paths use the process ANSI code page; use paths
representable in that code page. Paths containing spaces work when quoted.
No crypto library is linked to the application. Verification needs Python 3 and
an OpenSSL executable; on Windows, place OpenSSL on `PATH` or give its full path
with `--openssl`.

## Run with a disposable generated key

```sh
./p11lab-smoke --module /path/to/provider.so --token-label 'Test token' \
  --pin-file /path/to/pin-file --output smoke-result --key-mode generated
python3 verify.py smoke-result
```

Native Windows example:

```bat
p11lab-smoke.exe --module "C:\providers\provider.dll" --token-label "Test token" --pin-file "C:\secrets\pin" --output smoke-result --key-mode generated
py -3 verify.py smoke-result --openssl "C:\OpenSSL\bin\openssl.exe"
```

A remote provider needs a compatible local client module and transport
configuration. A Docker network alone does not make the provider's module
loadable in the application process. Configure the module through its supported
environment/configuration before invoking this application.

`--output` must name a new directory whose parent already exists. The application
creates it before any provider mutation and refuses to reuse it. A failed attempt
can leave this owned directory empty or partially populated; retry with a new
directory. Exit status is `0` for successful export and provider cleanup, `2` for
argument/output-directory errors, and `1` for provider or subsequent I/O failures.
A successful export still requires independent verification.

The token label is an exact 1..32-byte label, padded with spaces for comparison
against PKCS11's fixed-width field. Zero matches and duplicate matches fail.
Generated mode requires `CKM_EC_KEY_PAIR_GEN` and signing with `CKM_ECDSA`; it
creates session objects (`CKA_TOKEN=false`) and destroys only its own generated
objects. It uses a read/write session. Existing tokens are never initialized,
reset, or cleared. Module discovery selects the standard `PKCS 11` interface with
`C_GetInterface` when exported, otherwise `C_GetFunctionList`. An error from an
available discovery function is reported without falling back.

A PIN file contains exact raw bytes: no newline trimming or text conversion.
Use a private credential file without an accidental final newline. An empty file
passes a non-null pointer with length zero; omitting the option makes no login
call. Omission is accepted for a token that does not declare login required; if
its particular key requires login, its native error remains visible. A token
that declares login required needs the option. PIN contents and credential hashes
are never printed or exported, and the in-process buffer is wiped. PINs are
bounded to 4096 bytes. Protected authentication paths and per-use
`CKU_CONTEXT_SPECIFIC` authentication are outside this initial application.

## Run with an existing signing key

```sh
./p11lab-smoke --module /path/to/provider.so --token-label 'Test token' \
  --pin-file /path/to/pin-file --output existing-result --key-mode existing --key-id 42
python3 verify.py existing-result
```

`--key-id` is a nonempty, even-length hexadecimal encoding of the exact `CKA_ID`
(up to 128 bytes). Existing mode uses a read-only session, selects exactly one
EC private key, and never destroys existing objects. It obtains a unique public
EC object with the same ID, or reads the public attributes of the private object
when no public object exists. Duplicate objects fail, including duplicates spread
across search pages. Named-curve parameters must identify P256, and the point must
be a canonical DER OCTET STRING containing a 65-byte uncompressed point.

Some signing-only providers cannot expose public attributes. Supply an explicit
public key instead; this declaration is recorded as `declared-input` in the result.
The input is canonical DER/SPKI for an uncompressed named-curve P256 key. Convert
a provisioned PEM public key using OpenSSL:

```sh
openssl pkey -pubin -in provisioned-public.pem -outform DER -out provisioned-public.der
./p11lab-smoke --module /path/to/provider.so --token-label 'Test token' \
  --pin-file /path/to/pin-file --output declared-result --key-mode existing \
  --key-id 42 --public-key provisioned-public.der
python3 verify.py declared-result
```

Independent verification detects a declared public key that does not correspond
to the private key. Compressed points, explicit curve parameters, RSA fallback,
and integrated hash/sign mechanisms are future extensions.

## Artifacts and observation limits

The exact message is the ASCII bytes `P11Lab independent PKCS11 smoke v1` followed
by one LF byte. Its SHA256 digest is
`e8234db4ec58c86bb2f225423bc8d8ee8abdc528aef88c92df632f82a91573f3`.
`CKM_ECDSA` signs those 32 digest bytes; OpenSSL `dgst -sha256` hashes the exported
message independently. Generation, public export and signing occur in one process
before finalization, supporting ephemeral providers.

The output files are `message.bin`, `digest.bin`, `signature.raw` (64-byte R||S),
`signature.der`, `public-key.der` (SPKI), `public-key.pem`, and `result.json`.
The schema-1 result records the actual signing mechanism, key mode, public-key
source, slot, interface/library versions, and session/token flags. It is written
last, after provider cleanup succeeds. Retain application exit status and the
independent verifier result along with these public files; file presence alone
is insufficient run evidence. The verifier rejects altered message/digest input
and proves that OpenSSL rejects an altered message after accepting the original.

Native failures include the operation and unchanged numeric `CK_RV` on stderr.
Cleanup failures are also reported without concealing the primary failure. There
are no retries of login, generation, signing or other mutations. Enumeration and
attribute size/fetch pairs are read-only, bounded, and fail if the advertised
capacity changes. Signature output uses one bounded signing call. Enumeration is
bounded to 4096 slots/mechanisms; public attributes to 1024 bytes; paths to 4096
bytes. DER parsing and signature conversion reject malformed encodings and
out-of-range/zero P256 scalars. OpenSSL checks the public key and signature as the
independent cryptographic oracle.

This tests one application's operation against a provider. It does not establish
provider-wide qualification, certification, or completeness of other workloads.
The Linux standalone suite uses a newly owned temporary SoftHSM token store when
host tools are available and a narrowly scoped native fault fixture for error
contracts. Run it from this directory:

```sh
python3 -m unittest discover -s tests -v
```

The test harness itself currently targets Linux. Native Windows/MSVC build and
execution need their own platform validation. See [PROVENANCE.md](PROVENANCE.md)
for header licensing and its immutable source identity.
