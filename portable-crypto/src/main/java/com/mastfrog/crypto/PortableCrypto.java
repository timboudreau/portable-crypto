/*
 * The MIT License
 *
 * Copyright 2018 Tim Boudreau.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.mastfrog.crypto;

import static com.mastfrog.crypto.CryptoConfig.BLOWFISH;
import static com.mastfrog.crypto.Features.DETERMINISTIC_TEST_MODE;
import static com.mastfrog.crypto.Features.ENCRYPT;
import static com.mastfrog.crypto.Features.LOG;
import static com.mastfrog.crypto.Features.MAC;
import com.mastfrog.function.misc.QuietAutoClosable;
import com.mastfrog.util.collections.ArrayUtils;
import static com.mastfrog.util.preconditions.Checks.notNull;
import com.mastfrog.util.preconditions.Exceptions;
import com.mastfrog.util.strings.Strings;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.Random;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Basic password-based encryption with (optional) hmac, configured and tested
 * to interoperate cleanly with the NodeJS implementation of this library.
 * <p>
 * Algorithm configuration for encryption and mac generation is controlled by
 * the CryptoConfig and MacConfig objects passed to the constructor. Two
 * recommended default crypto configs are available: BLOWFISH and AES128. One
 * recommended MacConfig is available - MacConfig.HMAC256. If you choose to
 * provide your own parameters or choose a different algorithm, be aware that it
 * is very easy to create a configuration that does not work.
 * </p>
 * <h2>What It Does</h2>
 * <p>
 * Key generation from the password is the first step. All of the algorithms
 * used have a bit count limit on the key size (blowfish: 448 bits, AES: 128
 * bits); for passwords longer than the key size, a key of the maximum size is
 * generated, and the bytes of the input password wrap around zero, all such
 * bytes being xor'd with the bytes from the previous pass until the password is
 * fully represented, with all bits of it affecting the generated key.
 * </p><p>
 * Then we encrypt using the provided algorithm (with either of the provided
 * CryptoConfig implementations we are using CBC and PKCS5 padding).
 * </p><p>
 * Mac generation, if enabled, uses the following inputs:</p>
 * <ul>
 * <li>The mac is initialized using the hash (by default, SHA-256) of the key
 * generated from the password</li>
 * <li>A 16 byte salt, the first 8 bytes of which are the current time in
 * millis-since-epoch (this is checked by the mac verification code), and the
 * second 8 bytes of which are random</li>
 * <li>The encrypted bytes</li>
 * </ul>
 * <p>
 * Encoding and decoding Base64 is done using <code>java.util.Base64</code> (the
 * default encoder/decoder, not the MIME or URL ones), whose output is readable
 * by NodeJS's <code>Buffer.from(string, 'base64')</code>.
 * </p>
 *
 * @author Tim Boudreau
 */
public final class PortableCrypto implements QuietAutoClosable {

    private static final long TIMESTAMP_BASE = 1170786968198L;

    private final CryptoConfig cryptoConfig;
    private final byte[] key;
    private final MacConfig macConfig;
    private final Set<Features> features;
    private final Random rnd;

    /**
     * Create a new PortableCrypto with the default configuration of
     * Blowfish/CBC/Pkcs5Padding and SHA-256 hmac, with logging disabled.
     *
     * @param password The password
     */
    public PortableCrypto(String password) {
        this(null, password, null, null, MAC, ENCRYPT);
    }

    /**
     * Create a new PortableCrypto
     *
     * @param random Source of random numbers
     * @param password The password for encryption and decryption
     * @param config The crypto algorithm configuration
     * @param macConfig The hmac generation configuration
     * @param features The features to enable (mac generation, logging,
     * deterministic test mode)
     */
    public PortableCrypto(Random random, String password, CryptoConfig config, MacConfig macConfig, Features... features) {
        this.rnd = random == null ? defaultRandom() : random;
        this.features = toSet(features);
        if (this.features.isEmpty()) {
            System.err.println("PortableCrypto created configured for neither encryption nor mac generation - "
                    + " it will simply return the bytes you pass it.  Be sure this is what you want.");
        }
        this.cryptoConfig = config == null ? BLOWFISH : config;
        this.macConfig = macConfig == null ? MacConfig.HMAC256 : macConfig;
        key = createKey(notNull("password", password));
        if (this.features.contains(LOG)) {
            System.err.println("INIT: features: " + Strings.join(" ", this.features));
            System.err.println("INIT: config: " + this.cryptoConfig);
            System.err.println("INIT: mac: " + this.macConfig);
        }
    }

    static Random defaultRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            return Exceptions.chuck(ex);
        }
    }

    static Set<Features> toSet(Features... features) {
        EnumSet<Features> result = EnumSet.noneOf(Features.class);
        result.addAll(Arrays.asList(features));
        return result;
    }

    /**
     * For the paranoid, overwrites the key array.
     */
    public void close() {
        Arrays.fill(key, (byte) 0);
    }

    byte[] createKey(String password) {
        // Coerces the password into the available bits,
        // either by repeating it if shorter than the needed number
        // of bits, or wrapping around and xor'ing if longer
        byte[] key = password.getBytes(UTF_8);
        int bits = (key.length * 8);
        if (bits > cryptoConfig.keyBitLimit) {
            int amt = cryptoConfig.keyByteLimit();
            byte[] nue = new byte[amt];
            System.arraycopy(key, 0, nue, 0, amt);
            int pos = amt;
            while (pos < key.length) {
                for (int i = 0; i < nue.length && pos < key.length; i++) {
                    nue[i] ^= key[pos++];
                }
            }
            key = nue;
        }
        return key;
    }

    byte[] newInitializationVector() {
        byte[] result = new byte[cryptoConfig.ivSize];
        if (features.contains(DETERMINISTIC_TEST_MODE)) {
            Arrays.fill(result, (byte) 88); // ASCII 'X' / 0x58
        } else {
            rnd.nextBytes(result);
        }
        return result;
    }

    private Cipher encipher(IvParameterSpec iv) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, cryptoConfig.keyAlgorithm);
            Cipher enCipher = Cipher.getInstance(cryptoConfig.cryptAlgorithm);
            enCipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            return enCipher;
        } catch (Exception e) {
            return Exceptions.chuck(e);
        }
    }

    private Cipher decipher(IvParameterSpec iv) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, cryptoConfig.keyAlgorithm);
            Cipher deCipher = Cipher.getInstance(cryptoConfig.cryptAlgorithm);

            deCipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
            return deCipher;
        } catch (Exception e) {
            return Exceptions.chuck(e);
        }
    }

    private byte[] salt() {
        byte[] salt = new byte[macConfig.saltLength];
        long time = features.contains(DETERMINISTIC_TEST_MODE)
                ? 1000
                : System.currentTimeMillis() - TIMESTAMP_BASE;
        ByteBuffer buf = ByteBuffer.allocate(macConfig.saltLength);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putLong(time);
        if (features.contains(LOG)) {
            System.err.println("ENCRYPT-MAC: salt-timestamp: " + Instant.ofEpochMilli(time) + " - " + time);
        }
        if (features.contains(DETERMINISTIC_TEST_MODE)) {
            buf.position(buf.capacity());
        } else {
            byte[] rndBytes = new byte[buf.capacity() - buf.position()];
            rnd.nextBytes(rndBytes);
            buf.put(rndBytes);
        }
        buf.flip();
        buf.get(salt);
        return salt;
    }

    /**
     * Encrypt the passed byte array.
     *
     * @param bytes Some bytes to encrypt
     * @return An encrypted representation of the bytes
     */
    public byte[] encrypt(byte[] bytes) {
        byte[] encrypted;
        if (features.contains(ENCRYPT)) {
            encrypted = _encrypt(bytes);
        } else {
            encrypted = bytes;
        }
        if (!features.contains(MAC)) {
            return encrypted;
        }
        try {
            byte[] salt = salt();
            byte[] keyHash = MessageDigest.getInstance(macConfig.keyHashAlgorithm).digest(key);
            final SecretKeySpec secretKeySpec = new SecretKeySpec(keyHash, macConfig.macAlgorithm);
            final Mac hmac = Mac.getInstance(macConfig.macAlgorithm);
            hmac.init(secretKeySpec);
            hmac.update(salt);
            hmac.update(encrypted);
            byte[] mac = hmac.doFinal();
            if (features.contains(LOG)) {
                System.err.println("ENCRYPT-MAC: salt: " + Strings.toPaddedHex(salt, " "));
                System.err.println("ENCRYPT-MAC: mac: " + Strings.toPaddedHex(mac, " "));
            }
            return ArrayUtils.concatenate(salt, mac, encrypted);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            return Exceptions.chuck(ex);
        }
    }

    private static final long ONE_DAY_MILLIS = 1000 * 60 * 60 * 24;

    /**
     * Get the minimum possible size of a decryptable payload - the length of a
     * payload that encrypts at least one byte. This is the initialization
     * vector length, and if hmacs are enabled, adding in the mac salt length
     * and the length of the hmac.
     *
     * @return The minimum number of bytes, below which it is not useful to pass
     * bytes in to be decrypted
     */
    public int minDecryptionDataLength() {
        int result = cryptoConfig.ivSize;
        if (features.contains(MAC)) {
            result += macConfig.saltLength + macConfig.macLength;
        }
        return result + 1;
    }

    /**
     * Decrypt the passed byte array.
     *
     * @param data The data to decrypt
     * @return The decrypted byte array
     */
    public byte[] decrypt(byte[] data) {
        if (!features.contains(MAC) && !features.contains(ENCRYPT)) {
            return data;
        }
        if (!features.contains(MAC)) {
            if (!features.contains(ENCRYPT)) {
                return data;
            }
            if (data.length <= cryptoConfig.ivSize) {
                throw new IllegalArgumentException("Data length " + data.length
                        + " is less than the minimum initialization vector length.");
            }
            byte[][] split = ArrayUtils.split(data, cryptoConfig.ivSize);
            return _decrypt(split[0], split[1]);
        }
        try {
            byte[][] split = ArrayUtils.split(data, macConfig.saltLength, macConfig.saltLength + macConfig.macLength,
                    macConfig.saltLength + macConfig.macLength + cryptoConfig.ivSize);
            byte[] salt = split[0];
            byte[] mac = split[1];
            byte[] iv = split[2];
            byte[] toDecrypt = split[3];
            ByteBuffer saltBuffer = ByteBuffer.wrap(salt);

            long timestamp = saltBuffer.getLong() + TIMESTAMP_BASE;
            if (features.contains(LOG)) {
                System.err.println("DECRYPT-MAC: salt: " + Strings.toPaddedHex(salt, " "));
                System.err.println("DECRYPT-MAC: salt-timestamp: " + timestamp + " - "
                        + Instant.ofEpochMilli(timestamp));
                System.err.println("DECYRPT-MAC: iv: " + Strings.toPaddedHex(iv, " "));
                System.err.println("DECRYPT-MAC: mac-received: " + Strings.toPaddedHex(mac, " "));
            }
            if (System.currentTimeMillis() + ONE_DAY_MILLIS < timestamp || timestamp < TIMESTAMP_BASE) {
                throw new IllegalArgumentException("Invalid time component " + new Date(timestamp));
            }
            byte[] keyHash = MessageDigest.getInstance(macConfig.keyHashAlgorithm).digest(key);
            final SecretKeySpec secretKeySpec = new SecretKeySpec(keyHash, macConfig.macAlgorithm);
            final Mac hmac = Mac.getInstance(macConfig.macAlgorithm);
            hmac.init(secretKeySpec);
            hmac.update(salt);
            hmac.update(iv);
            hmac.update(toDecrypt);
            byte[] computedMac = hmac.doFinal();
            boolean macValidated = Arrays.equals(mac, computedMac);
            if (features.contains(LOG)) {
                System.err.println("DECRYPT-MAC: mac-computed: " + Strings.toPaddedHex(computedMac, " "));
                System.err.println("DECRYPT-MAC: key-hash: " + Strings.toPaddedHex(keyHash, " "));
            }
            if (!macValidated) {
                throw new IllegalArgumentException("Hmac comparsion failed");
            }
            if (!features.contains(ENCRYPT)) {
                return ArrayUtils.concatenate(iv, toDecrypt);
            }
            return _decrypt(iv, toDecrypt);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            return Exceptions.chuck(ex);
        }
    }

    private byte[] _decrypt(byte[] iv, byte[] data) {
        if (data.length == 0) {
            return data;
        }
        try {
            Cipher decipher = decipher(new IvParameterSpec(iv));
            for (int i = 0; i < cryptoConfig.rounds; i++) {
                data = decipher.doFinal(data);
            }
            return data;
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            return Exceptions.chuck(ex);
        }
    }

    private byte[] _encrypt(byte[] bytes) {
        if (bytes.length == 0) {
            return bytes;
        }
        byte[] iv = newInitializationVector();
        if (features.contains(LOG)) {
            System.err.println("ENC: iv: " + Strings.toPaddedHex(iv, " "));
        }
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        try {
            Cipher encipher = encipher(ivSpec);
            for (int i = 0; i < cryptoConfig.rounds; i++) {
                bytes = encipher.doFinal(bytes);
            }
            if (features.contains(LOG)) {
                System.err.println("ENC: payload-length: " + bytes.length);
            }
            return ArrayUtils.concatenate(iv, bytes);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            return Exceptions.chuck(ex);
        }
    }

    /**
     * Encrypt a passed UTF-8 string.
     *
     * @param cleartext The text to encrypt
     * @return The encrypted bytes
     */
    public byte[] encrypt(String cleartext) {
        return encrypt(cleartext.getBytes(UTF_8));
    }

    /**
     * Encrypt a passed UTF-8 string, returning the encrypted bytes as a Base64
     * string.
     *
     * @param clearText The text to encrypt
     * @return A Base64 string
     */
    public String encryptToString(String clearText) {
        return Base64.getEncoder().encodeToString(encrypt(clearText));
    }

    /**
     * Encrypt the passed byte array, returning the encrypted bytes as a Base64
     * string.
     *
     * @param clearText The text to encrypt
     * @return A Base64 string
     */
    public String encryptToString(byte[] bytes) {
        return Base64.getEncoder().encodeToString(encrypt(bytes));
    }

    /**
     * Decrypt the passed UTF-8 string, returning the decrypted bytes.
     *
     * @param clearText The text to encrypt
     * @return A Base64 string
     */
    public byte[] decryptToBytes(String base64data) {
        return decrypt(Base64.getDecoder().decode(base64data));
    }

    /**
     * Decrypt the passed UTF-8 string, returning the decrypted bytes as a UTF-8
     * string.
     *
     * @param encrypted The text to decrypt
     * @return A Base64 string
     */
    public String decrypt(String encrypted) {
        byte[] decrypted = decrypt(Base64.getDecoder().decode(encrypted));
        return new String(decrypted, UTF_8);
    }
}
