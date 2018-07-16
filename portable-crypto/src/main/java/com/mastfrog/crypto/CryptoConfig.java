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

import com.mastfrog.util.strings.Strings;

/**
 * Configuration of the encryption algorithm used by {@link PortableCrypto}. Your best bet is to use one of the
 * predefined constants on this class.
 *
 * @author Tim Boudreau
 */
public final class CryptoConfig {

    public static CryptoConfig BLOWFISH = new CryptoConfig(448, "Blowfish", 8, "Blowfish/CBC/PKCS5Padding", 1);
    public static CryptoConfig AES128 = new CryptoConfig( 128, "AES", 16, "AES/CBC/PKCS5Padding", 1 );

    final int keyBitLimit;
    final String keyAlgorithm;
    final int ivSize;
    final String cryptAlgorithm;
    final int rounds;

    public CryptoConfig(int keyBitLimit, String keyAlgorithm, int ivSize, String cryptAlgorithm, int rounds) {
        if ( keyBitLimit % 8 != 0 ) {
            throw new IllegalArgumentException( "Bit limit not divisible by 8:" + keyBitLimit );
        }
        this.keyBitLimit = keyBitLimit;
        this.keyAlgorithm = keyAlgorithm;
        this.ivSize = ivSize;
        this.cryptAlgorithm = cryptAlgorithm;
        this.rounds = rounds;
    }

    int keyByteLimit() {
        return keyBitLimit / 8;
    }

    @Override
    public String toString() {
        return Strings.join( ' ', "key-bits", keyBitLimit, "iv-size", ivSize, "key-algorithm", keyAlgorithm,
                "crypt-algorithm", cryptAlgorithm ).toString();
    }

}
