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
import com.mastfrog.util.Streams;
import com.mastfrog.util.Strings;
import com.mastfrog.util.collections.ArrayUtils;
import com.mastfrog.util.strings.RandomStrings;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import static java.nio.charset.StandardCharsets.UTF_8;
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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 *
 * @author tim
 */
public class PortableCryptoTest {

    private PortableCrypto crypto;
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
        crypto = new PortableCrypto(rnd, pass, CryptoConfig.BLOWFISH, MacConfig.HMAC256, MAC, ENCRYPT);
        testOneCrypto("blowfish-mac");
    }

    @Test
    public void testBlowfishNoMac() throws Throwable {
        crypto = new PortableCrypto(rnd, pass, CryptoConfig.BLOWFISH, MacConfig.HMAC256, ENCRYPT);
        testOneCrypto("blowfish-nomac");
    }

    @Test
    public void testAESMac() throws Throwable {
        crypto = new PortableCrypto(rnd, pass, CryptoConfig.AES128, MacConfig.HMAC256, MAC, ENCRYPT);
        testOneCrypto("aes-mac");
    }

    @Test
    public void testAESNoMac() throws Throwable {
        crypto = new PortableCrypto(rnd, pass, CryptoConfig.AES128, MacConfig.HMAC256, ENCRYPT);
        testOneCrypto("aes-nomac");
    }

    @Test
    public void testJustMac() throws Throwable {
        crypto = new PortableCrypto(rnd, pass, CryptoConfig.AES128, MacConfig.HMAC256, MAC);
        String macd = crypto.encryptToString("Test just using a mac with no encryption at all");
        String unmacd = crypto.decrypt(macd);
        assertEquals("Test just using a mac with no encryption at all", unmacd);
    }

    private void testOneCrypto(String config) throws Throwable {
        for (String s : strings) {
            testOne(s, config);
        }
    }

    String[] args(String... args) {
        return args;
    }

    private final void testOne(String in, String config) throws Throwable {
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
            default:
                fail(config);
                return;
        }
        byte[] encBytes = crypto.encrypt(in);
        assertTrue(config, encBytes.length > crypto.minDecryptionDataLength());
        byte[] out = crypto.decrypt(encBytes);
        assertArrayEquals(config, in.getBytes(UTF_8), out);

        String encString = crypto.encryptToString(in);
        String decString = crypto.decrypt(encString);
        assertEquals(config, in, decString);
        if (canRunNode()) {
            byte[] encByNode = runNode(in.getBytes(UTF_8), false, args);

            byte[] decByNode = runNode(encBytes, true, args);

            out = crypto.decrypt(encByNode);
            assertArrayEquals(config, in.getBytes(UTF_8), out);

            assertArrayEquals(config, in.getBytes(UTF_8), decByNode);
        } else {
            System.err.println("NodeJS too old to run node tests: ");
        }
    }

    private byte[] runNode(byte[] in, boolean decrypt, String... args) throws IOException, URISyntaxException, InterruptedException {
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
            try (InputStream inp = p.getInputStream()) {
                Streams.copy(inp, out);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        t.start();

        final ByteArrayOutputStream err = new ByteArrayOutputStream();
        Thread te = new Thread(() -> {
            ph.arriveAndAwaitAdvance();
            try (InputStream inp = p.getErrorStream()) {
                Streams.copy(inp, err);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        te.start();

        ph.arriveAndDeregister();
        if (in != null) {
            try (OutputStream o = p.getOutputStream()) {
                o.write(in);
            }
        }

        int code = p.waitFor();
        assertEquals(Strings.join(' ', args) + ": " + new String(err.toByteArray(), UTF_8), 0, code);

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

        Process p = pb.start();
        Phaser ph = new Phaser(3);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread t = new Thread(() -> {
            ph.arriveAndAwaitAdvance();
            try (InputStream inp = p.getInputStream()) {
                Streams.copy(inp, out);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        t.start();

        final ByteArrayOutputStream err = new ByteArrayOutputStream();
        Thread te = new Thread(() -> {
            ph.arriveAndAwaitAdvance();
            try (InputStream inp = p.getErrorStream()) {
                Streams.copy(inp, err);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        te.start();

        ph.arriveAndDeregister();

        int code = p.waitFor();
        String outString = new String(out.toByteArray(), UTF_8);
        String errString = new String(err.toByteArray(), UTF_8);
        nodeMajorVersion = outString;
        if (code != 0) {
            System.err.println("node --version exited with " + code + ": \n" + errString);
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
