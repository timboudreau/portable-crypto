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

import com.mastfrog.util.Strings;

/**
 * Configuration for mac generation.
 *
 * @author Tim Boudreau
 */
public final class MacConfig {

    public final int saltLength;
    public final int macLength;
    public final String macAlgorithm;
    public final String keyHashAlgorithm;

    /**
     * Default parameters for HMAC generation using HmacSHA256 and SHA-256.
     */
    public static MacConfig HMAC256 = new MacConfig( 16, 32, "HmacSHA256", "SHA-256" );

    public MacConfig(int saltLength, int macLength, String macAlgorithm, String keyHashAlgorithm) {
        this.saltLength = saltLength;
        this.macLength = macLength;
        this.macAlgorithm = macAlgorithm;
        this.keyHashAlgorithm = keyHashAlgorithm;
    }

    @Override
    public String toString() {
        return Strings.join( ' ', "salt-length", saltLength, "mac-length", macLength,
                "mac-algorithm", macAlgorithm, "key-hash-algorithm", keyHashAlgorithm ).toString();
    }

}
