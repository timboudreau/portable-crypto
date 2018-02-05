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

/**
 * Features which can be enabled on {@link PortableCrypto}.
 *
 * @author Tim Boudreau
 */
public enum Features {

    /**
     * Generate a signed hmac to ensure the message was not altered in transit.
     */
    MAC("mac"),
    /**
     * Encrypt (if not set, only signing will be done).
     */
    ENCRYPT("encrypt"),
    /**
     * <b>For testing only!</b> This feature disables all randomness, so that for the same input the library gives the
     * same output. It is useful for debugging any differences in encoded and decoded buffers between languages, but it
     * also
     * <i>makes things very insecure!</i> and should never, ever be used in production.
     */
    DETERMINISTIC_TEST_MODE( "deterministic" ),
    /**
     * Log buffers to the standard error, for development-time debugging.
     */
    LOG( "log" );
    private final String name;

    Features(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
