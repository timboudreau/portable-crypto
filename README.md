Portable Crypto
===============

This project consists of two libraries, one in Java and one in NodeJS's Javascript, to
support strong encryption, with the specific goals of:

 * Following best practices
 * Minimal or no dependencies
 * Producing output readable by the other

Coming up with a crypto configuration that actually produces the same output using both
the JDK's cryptography support, and Node's built-in `crypto` library is more difficult
than it sounds.

Supports any algorithm either platform supports, by passing in configuration objects for
crypto config and mac generation.  Has built-in constants to support blowfish and aes128
encryption and sha256 hmacs.

Hmac generation is optional.

Usage
-----

### Java

Add `com.mastfrog` `portable-crypto` as a maven library using [this repository](https://timboudreau.com/builds),
or build it from source.  Then:

```java

PortableCrypto pcrypt = new PortableCrypto("iHazSecuritiez");

byte[] encrypted = pcrypt.encrypt("Look, Ma, I'm encrypted!");

// or

String encryptedString = pcrypt.encryptToString("Look, Ma, I'm the ace of base64");

// decrypt

byte[] decrypted = pcrypt.decrypt(encrypted);

assert Arrays.equals(decrypted, "Look, Ma, I'm encrypted".getBytes(UTF_8));

String decryptedString = pcrypt.decrypt(encryptedString);
assert decrypted.equals("Look, Ma, I'm the ace of base64");
```


### NodeJS

```javascript
const PortableCrypto = require('portable-crypto').PortableCrypto;

PortableCrypto pcrypt = new PortableCrypto("iHazSecuritiez");

let encrypted = pcrypt.encrypt("Look, Ma, I'm encrypted!");

// or

let encryptedString = pcrypt.encryptToString("Look, Ma, I'm the ace of base64");

// decrypt

let decrypted = pcrypt.decrypt(encrypted);

assert(Buffer.equals(decrypted, Buffer.from('Look, Ma, I'm encrypted','utf8'));

String decryptedString = pcrypt.decrypt(encryptedString);
assert.equals("Look, Ma, I'm the ace of base64", decryptedString);
```

The NodeJS version also supports command-line usage:

```
Usage: portable-crypto --passphrase "iHazSekurity"  --log --aes --in somefile.txt --out encryptedfile.b64

OPTIONS:

 -d | --decrypt - Decrypt instead of encrypt
 -a | --aes     - Use AES128 encryption instead of Blowfish
 -n | --nomac   - Don't generate an hmac to verify message integrity
 -p | --pass    - Use the passed password or passphrase
 -e | --passenv - Read the passphrase from an environment variable
 -v | --verbose - Log buffer contents for debugging
 -i | --in      - Read input from this file instead of stdin
 -o | --out     - Write binary output to this file instead of stdout
 -6 | --base64  - If encrypting, output base64 not binary encrypted data (encrypt only); if decrypting, decode base64 input
```
