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

import static com.mastfrog.crypto.Features.ENCRYPT;
import static com.mastfrog.crypto.Features.MAC;
import com.mastfrog.util.collections.ArrayUtils;
import com.mastfrog.util.file.FileUtils;
import com.mastfrog.util.streams.Streams;
import com.mastfrog.util.strings.RandomStrings;
import com.mastfrog.util.strings.Strings;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Phaser;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 *
 * @author tim
 */
public class PortableCryptoTest {

    Random rnd = new Random(23);
    String pass = new RandomStrings(rnd).get(300);

    private final String[] strings = new String[]{
        "just a little something",
        "hey something more this here is and it's a big thing isn't it",
        "You may not get a real physical path and real path may be a "
        + "symbolic link. To get physical path use realpath command. "
        + "The realpath command uses the realpath() function to resolve "
        + "all symbolic links, extra / characters and references to /./ "
        + "and /../ in path. This is useful for shell scripting and "
        + "security related applications."
    };

    @Test
    public void testBlowfishMac() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.BLOWFISH, MacConfig.HMAC256, MAC, ENCRYPT);
        testOneCrypto("blowfish-mac", crypto);
    }

    @Test
    public void testBlowfishNoMac() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.BLOWFISH, MacConfig.HMAC256, ENCRYPT);
        testOneCrypto("blowfish-nomac", crypto);
    }

    @Test
    public void testAESMac() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.AES128, MacConfig.HMAC256, MAC, ENCRYPT);
        testOneCrypto("aes-mac", crypto);
    }

    @Test
    public void testAESNoMac() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.AES128, MacConfig.HMAC256, ENCRYPT);
        testOneCrypto("aes-nomac", crypto);
    }

//    @Test
    public void testChaCha() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.CHACHA, MacConfig.HMAC256, ENCRYPT, MAC);
        testOneCrypto("chacha", crypto);
    }

//    @Test
    public void testChaChaNoMac() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.CHACHA, MacConfig.HMAC256, ENCRYPT);
        testOneCrypto("chacha-nomac", crypto);
    }

//    @Test
    public void testChaChaPoly1305() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.CHACHA_POLY1305, MacConfig.HMAC256, ENCRYPT, MAC);
        testOneCrypto("chacha-poly1305", crypto);
    }

    @Test
    public void testChaChaPoly1305NoMac() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.CHACHA_POLY1305, MacConfig.HMAC256, ENCRYPT);
        testOneCrypto("chacha-poly1305-nomac", crypto);
    }

//    @Test
    public void testJustMac() throws Throwable {
        PortableCrypto crypto = new PortableCrypto(rnd, pass, CryptoConfig.AES128, MacConfig.HMAC256, MAC);
        String macd = crypto.encryptToString("Test just using a mac with no encryption at all");
        String unmacd = crypto.decrypt(macd);
        assertEquals("Test just using a mac with no encryption at all", unmacd);
    }

    private void testOneCrypto(String config, PortableCrypto crypto) throws Throwable {
        for (String s : strings) {
            selfTest(crypto);
            testOne(s, config, crypto);
        }
    }

    String[] args(String... args) {
        return args;
    }

    private void selfTest(PortableCrypto crypto) {
        if (crypto.isEnabled(Features.ENCRYPT)) {
            assertCanEncryptAndDecrypt("This is some stuff to encrypt", crypto);
        }
    }

    private void assertCanEncryptAndDecrypt(String what, PortableCrypto crypto) {
        try {
            byte[] encrypted = crypto.encrypt(what.getBytes(UTF_8));
            byte[] decrypted = crypto.decrypt(encrypted);
            String dec = new String(decrypted, UTF_8);
            assertEquals("Decryption corrupted with " + crypto, what, dec);
            String encryptedString = crypto.encryptToString(what);
            String decryptedString = crypto.decrypt(encryptedString);
            assertEquals("Decription of string corrupted with " + crypto, what, decryptedString);
        } catch (AssertionError ae) {
            throw ae;
        } catch (Exception | Error ex) {
            throw new AssertionError("Failed with " + crypto + " encrypting '" + what + "'", ex);
        }
    }

    private final void testOne(String in, String config, PortableCrypto crypto) throws Throwable {
        String args[];
        switch (config) {
            case "aes-mac":
                args = args("-p", pass, "-a");
                break;
            case "aes-nomac":
                args = args("-n", "-p", pass, "-a");
                break;
            case "blowfish-nomac":
                args = args("-n", "-p", pass);
                break;
            case "blowfish-mac":
                args = args("-p", pass);
                break;
            case "chacha":
                args = args("-h", "-p", pass);
                break;
            case "chacha-nomac":
                args = args("-n", "-h", "-p", pass);
                break;
            case "chacha-poly1305":
                args = args("-l", "-p", pass);
                break;
            case "chacha-poly1305-nomac":
                args = args("-n", "-l", "-p", pass);
                break;
            default:
                fail(config);
                return;
        }
        byte[] encBytes = crypto.encrypt(in);
        switch (Arrays.asList(strings).indexOf(in)) {
            case 0:
                switch (config) {
                    case "aes-mac":
                        assertEquals(toString(encBytes), 96, encBytes.length);
                        break;
                    case "blowfish-mac":
                        assertEquals(toString(encBytes), 80, encBytes.length);
                        break;
                    case "blowfish-nomac":
                        assertEquals(toString(encBytes), 32, encBytes.length);
                        break;
                    case "aes-nomac":
                        assertEquals(toString(encBytes), 48, encBytes.length);
                        break;
                }
                break;
            case 1:
                switch (config) {
                    case "aes-mac":
                        assertEquals(toString(encBytes), 128, encBytes.length);
                        break;
                    case "blowfish-mac":
                        assertEquals(toString(encBytes), 120, encBytes.length);
                        break;
                    case "blowfish-nomac":
                        assertEquals(toString(encBytes), 72, encBytes.length);
                        break;
                    case "aes-nomac":
                        assertEquals(toString(encBytes), 80, encBytes.length);
                        break;
                }
                break;
            case 2:
                switch (config) {
                    case "aes-mac":
                        assertEquals(toString(encBytes), 400, encBytes.length);
                        break;
                    case "blowfish-mac":
                        assertEquals(toString(encBytes), 384, encBytes.length);
                        break;
                    case "blowfish-nomac":
                        assertEquals(toString(encBytes), 336, encBytes.length);
                        break;
                    case "aes-nomac":
                        assertEquals(toString(encBytes), 352, encBytes.length);
                        break;
                }
                break;
            default:
                fail("Huh? " + in);
        }
        assertTrue(config, encBytes.length > crypto.minDecryptionDataLength());
        byte[] inBytes = in.getBytes(UTF_8);
        byte[] out = crypto.decrypt(encBytes);

        if (inBytes.length < out.length) {
            // XXX Padding gets returned, only on Solaris - this
            // probably requires a long-term fix of including the length
            // in the encrypted payload
            out = Arrays.copyOf(out, inBytes.length);
        }

        String decrypted = new String(out, UTF_8);
        assertEquals(config + " '" + in + "' -> '" + decrypted, in.length(),
                decrypted.length());
        assertEquals(config, "'" + in + "'", "'" + decrypted + "'");
        assertArrayEquals(config, inBytes, out);

        String encString = crypto.encryptToString(in);
        String decString = crypto.decrypt(encString).substring(0, in.length());
        assertEquals(config, in, decString);
        if (canRunNode()) {
            byte[] encByNode = runNode(crypto, inBytes, false, args);
            byte[] decByNode = runNode(crypto, encBytes, true, args);
            out = crypto.decrypt(encByNode);
            assertArrayEquals(config, inBytes, out);
            assertArrayEquals(config, inBytes, decByNode);
        } else {
            System.err.println("NodeJS too old to run node tests: ");
        }
    }

    private static String toString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (b >= 33 && b <= 126 && b != ' ') {
                sb.append((char) b);
            } else {
                String x = Integer.toHexString(b & 0xFF);
                if (x.length() == 1) {
                    x = "0" + x;
                }
                if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ' ') {
                    sb.append(' ');
                }
                sb.append("0x").append(x).append(' ');
            }
        }
        return sb.toString();
    }

    private static void assertArrayEquals(String msg, byte[] a, byte[] b) {
        if (!Arrays.equals(a, b)) {
            int firstDifference = 0;
            for (int i = 0; i < Math.min(b.length, a.length); i++) {
                if (a[i] != b[i]) {
                    firstDifference = i;
                    break;
                }
            }
            byte[] aa = new byte[0];
            byte[] bb = new byte[0];
            if (firstDifference < a.length) {
                aa = new byte[a.length - firstDifference];
                System.arraycopy(a, firstDifference, aa, 0, aa.length);
            }
            if (firstDifference < b.length) {
                bb = new byte[b.length - firstDifference];
                System.arraycopy(b, firstDifference, bb, 0, bb.length);
            }

            fail(msg + " Byte arrays do not match. Lengths " + a.length + " and " + b.length
                    + ". First difference at " + firstDifference
                    + "\nTails:\n" + toString(aa) + "\n" + toString(bb)
                    + "\nFull:\n" + toString(a) + "\n" + toString(b)
            );
        }
    }

    static long ct = 0;

    private byte[] runNode(PortableCrypto crypto, byte[] in, boolean decrypt, String... args) throws IOException, URISyntaxException, InterruptedException {
        Path tmp = Paths.get(System.getProperty("java.io.tmpdir"));
        String suffix = Long.toString(System.currentTimeMillis(), 36) + new RandomStrings(rnd).get(3)
                + "_" + ct++;
        Path inFile = tmp.resolve(crypto.keyAlgorithm() + suffix + ".in");
        Path outFile = tmp.resolve(crypto.keyAlgorithm() + suffix + ".out");
        if (decrypt) {
            args = ArrayUtils.concatenate(args, new String[]{"-d"});
        }
        args = ArrayUtils.concatenate(args, new String[]{"--in", inFile.toString(), "--out", outFile.toString()});

        Files.write(inFile, in, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);

        List<String> l = new ArrayList<>(Arrays.asList(nodePath()));
        l.addAll(Arrays.asList(args));

        ProcessBuilder pb = new ProcessBuilder(l);

        Process p = pb.start();
        processes.add(p);

        Phaser ph = new Phaser(3);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread t = new Thread(() -> {
            ph.arriveAndAwaitAdvance();
            try ( InputStream inp = p.getInputStream()) {
                Streams.copy(inp, out);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        t.start();

        final ByteArrayOutputStream err = new ByteArrayOutputStream();
        Thread te = new Thread(() -> {
            ph.arriveAndAwaitAdvance();
            try ( InputStream inp = p.getErrorStream()) {
                Streams.copy(inp, err);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        te.start();

        ph.arriveAndDeregister();

        int code = p.waitFor();
        assertEquals("Node failed for " + crypto + ":\n"
                + " args " + Strings.join(' ', args) + "\n"
                + Strings.join(' ', args) + "\nError:\n" + new String(err.toByteArray(), UTF_8)
                + "\nOutput:\n" + new String(out.toByteArray(), UTF_8),
                 0, code);

        if (!Files.exists(outFile)) {
            fail("Outfile " + outFile + " not created");
        }

        return Files.readAllBytes(outFile);
    }

    private byte[] xrunNode(PortableCrypto crypto, byte[] in, boolean decrypt, String... args) throws IOException, URISyntaxException, InterruptedException {
        if (decrypt) {
            args = ArrayUtils.concatenate(args, new String[]{"-d"});
        }
        List<String> l = new ArrayList<>(Arrays.asList(nodePath()));
        l.addAll(Arrays.asList(args));

        ProcessBuilder pb = new ProcessBuilder(l);

        Process p = pb.start();
        processes.add(p);
        Phaser ph = new Phaser(3);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread t = new Thread(() -> {
            ph.arriveAndAwaitAdvance();
            try ( InputStream inp = p.getInputStream()) {
                Streams.copy(inp, out);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        t.start();

        final ByteArrayOutputStream err = new ByteArrayOutputStream();
        Thread te = new Thread(() -> {
            ph.arriveAndAwaitAdvance();
            try ( InputStream inp = p.getErrorStream()) {
                Streams.copy(inp, err);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        te.start();

        ph.arriveAndDeregister();
        if (in != null) {
            try ( OutputStream o = p.getOutputStream()) {
                o.write(in);
            }
        }

        int code = p.waitFor();
        assertEquals("Node failed for " + crypto + ":\n"
                + " args " + Strings.join(' ', args) + "\n"
                + Strings.join(' ', args) + ": " + new String(err.toByteArray(), UTF_8), 0, code);

        byte[] result = out.toByteArray();
        return result;
    }
    Set<Process> processes = new HashSet<>();

    @After
    public void cleanup() {
        for (Process p : processes) {
            try {
                p.exitValue();
            } catch (Exception ex) {
                p.destroy();
            }
        }
    }

    private static String np;

    private static String nodePath() throws IOException, URISyntaxException {
        if (np != null) {
            return np;
        }
        ProtectionDomain protectionDomain = PortableCrypto.class.getProtectionDomain();
        URL location = protectionDomain.getCodeSource().getLocation();

        // See if an explicitly provided assets folder was passed to us;  if
        // not we will look for an "assets" folder belonging to this application
        File codebaseDir = new File(location.toURI()).getParentFile();
        if ("target".equals(codebaseDir.getName()) || "build".equals(codebaseDir.getName())) {
            codebaseDir = codebaseDir.getParentFile();
        }
        File f = new File(codebaseDir, "../portable-crypto-js/portable-crypto");
        return np = f.getCanonicalPath();
    }

    private static Boolean canRunNode;
    private static String nodeMajorVersion = "<could-not-run-node>";

    private static boolean canRunNode() throws IOException, InterruptedException {
        if (canRunNode != null) {
            return canRunNode;
        }
        ProcessBuilder pb = new ProcessBuilder("/usr/bin/env", "node", "--version");
        Path output = FileUtils.newTempFile("node-version");
        pb.redirectOutput(output.toFile());
        Process p = pb.start();
        int code = p.waitFor();
        String outString = FileUtils.readUTF8String(output).trim();
        FileUtils.deleteIfExists(output);
        nodeMajorVersion = outString;
        if (code != 0) {
            System.err.println("node --version exited with " + code + ": \n");
            canRunNode = false;
        } else {
            if (outString.startsWith("v0.")) {
                canRunNode = false;
            } else {
                Pattern pat = Pattern.compile("v(\\d+)\\..*");
                Matcher m = pat.matcher(outString);
                if (m.find()) {
                    int majorVersion = Integer.parseInt(m.group(1));
                    canRunNode = majorVersion > 8;
                } else {
                    canRunNode = false;
                }
            }
        }
        return canRunNode;
    }
}
