#!/usr/bin/env node
/*
 The MIT License (MIT)
 
 Copyright (c) 2018 Tim Boudreau
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
const crypto = require( 'crypto' );

const BLOWFISH = new CryptoConfig( 448, "blowfish", 8, 1 );
const AES128 = new CryptoConfig( 128, "aes-128-cbc", 16, 1 );

const HMAC256 = new MacConfig( 16, 32, "sha256", "sha256" );

const TIMESTAMP_BASE = 1170786968198;

const ONE_DAY_MILLIS = 1000 * 60 * 60 * 24;

const FEATURE_USE_MAC = "mac"
        , FEATURE_LOG = "log"
        , FEATURE_ENCRYPT = "encrypt"
        , FEATURE_DETERMINISTIC_TEST_MODE = "deterministic";

module.exports = {PortableCrypto, FEATURE_USE_MAC, FEATURE_LOG,
    FEATURE_DETERMINISTIC_TEST_MODE, BLOWFISH, AES128, HMAC256,
    CryptoConfig, MacConfig};

/**
 * Create a new PortableCrypto - 
 * Basic password-based encryption with (optional) hmac, configured and 
 * tested to interoperate cleanly with the Java implementation of this library.
 * <p>
 * Algorithm configuration for encryption and mac generation is controlled by the CryptoConfig and MacConfig objects
 * passed to the constructor. Two recommended default crypto configs are available: BLOWFISH and AES128. One recommended
 * MacConfig is available - MacConfig.HMAC256. If you choose to provide your own parameters or choose a different
 * algorithm, be aware that it is very easy to create a configuration that does not work.
 * </p>
 * <h2>What It Does</h2>
 * <p>
 * Key generation from the password is the first step. All of the algorithms used have a bit count limit on the key size
 * (blowfish: 448 bits, AES: 128 bits); for passwords longer than the key size, a key of the maximum size is generated,
 * and the bytes of the input password wrap around zero, all such bytes being xor'd with the bytes from the previous
 * pass until the password is fully represented, with all bits of it affecting the generated key.
 * </p><p>
 * Then we encrypt using the provided algorithm (with either of the provided CryptoConfig implementations we are using
 * CBC and PKCS5 padding).
 * </p><p>
 * Mac generation, if enabled, uses the following inputs:</p>
 * <ul>
 * <li>The mac is initialized using the hash (by default, SHA-256) of the key generated from the password</li>
 * <li>A 16 byte salt, the first 8 bytes of which are the current time in millis-since-epoch (this is checked by the mac
 * verification code), and the second 8 bytes of which are random</li>
 * <li>The encrypted bytes</li>
 * </ul>
 * <p>
 * Encoding and decoding Base64 is done using <code>java.util.Base64</code> (the default encoder/decoder, not the MIME
 * or URL ones), whose output is readable by NodeJS's <code>Buffer.from(string, 'base64')</code>.
 * </p>
 *
 * @param {type} password The password to use, as a UTF-8 string.
 * @param {type} cryptoConfig Crypto configuration - if unset, uses the default
 * @param {type} macConfig - Mac generation config - if unset, uses the default,
 * and irrelevant if features.mac is not truthy
 * @param {type} features - may be either an object with the features enabled
 * as boolean true - e.g. { mac : true, log : true }, or this and subsequent
 * arguments may be strings naming the features to enable
 * @author Tim Boudreau
 * 
 * @returns {nm$_portable-crypto.PortableCrypto}
 */
function PortableCrypto( password, cryptoConfig, macConfig, features ) {
    cryptoConfig = cryptoConfig || BLOWFISH;
    macConfig = macConfig || HMAC256;
    if ( typeof features === 'string' ) {
        let f = [];
        for ( var i = 2; i < arguments.length; i++ ) {
            var arg = arguments[i];
            if ( typeof arg === 'string' ) {
                f.push( arg );
            }
        }
        features = Features.apply( {}, f );
    }
    features = features || new Features( FEATURE_USE_MAC, FEATURE_ENCRYPT );

    if ( features.log ) {
        console.error( 'INIT: ' + features );
        console.error( 'INIT: ' + cryptoConfig )
        console.error( 'INIT: ' + macConfig );
    }

    const key = createKey( password, cryptoConfig );

    /**
     * Encrypt something, returning it as a Base64 encoded string.
     * 
     * @param {string|Buffer|object} data
     * @returns {PortableCrypto@call;encrypt@call;toString}
     */
    this.encryptToString = ( data ) => {
        return this.encrypt( data ).toString( 'base64' );
    }

    /**
     * Decrypt a buffer or Base64 encoded string to a UTF-8 string.
     * 
     * @param {type} data
     * @returns {PortableCrypto@call;decrypt@call;toString}
     */
    this.decryptToString = ( data ) => {
        return this.decrypt( data ).toString( 'utf8' );
    }

    function ensureInputBuffer( data ) {
        if ( typeof data === 'string' ) {
            return Buffer.from( data, 'utf8' );
        }
        if ( data ) {
            if ( !(data instanceof Buffer) ) {
                return ensureInputBuffer( JSON.stringify( data ) );
            }
        }
        return data;
    }

    function newInitializationVector( config ) {
        if ( features.deterministic ) {
            return Buffer.alloc( config.ivSize, 88 ); // ascii X / 0x58 hex
        } else {
            return crypto.randomBytes( config.ivSize );
        }
    }

    function newSalt( ) {
        let salt = Buffer.alloc( macConfig.saltLength, 0 );
        let time = features.deterministic ? 1000 :
                new Date().getTime() - TIMESTAMP_BASE;
        if ( features.log ) {
            console.error( 'ENCRYPT-MAC: salt-timestamp:', time + " - " + new Date( time + TIMESTAMP_BASE ) )
        }
        write64bit( time, salt, 0 );
        if ( !features.deterministic ) {
            crypto.randomFillSync( salt, 8, 8 );
        }
        return salt;
    }

    /**
     * Encrypt something - objects are converted to JSON,
     * Base64 strings are decoded, buffers are used as-is.
     * 
     * @param {Buffer|string|Object} data
     * @returns {PortableCrypto.encrypt.encrypted|nm$_portable-crypto.PortableCrypto.encrypt.encrypted|PortableCrypto._encrypt.buf|nm$_portable-crypto.PortableCrypto._encrypt.buf|Error|PortableCrypto.encrypt.result}
     */
    this.encrypt = ( data ) => {
        if ( !data ) {
            return new Error( 'Data null or undefined' );
        }
        data = ensureInputBuffer( data );
        const encrypted = features.encrypt ? _encrypt( data ) : data;
        if ( !features.mac ) {
            return encrypted;
        }
        let salt = newSalt( macConfig );

        let keyHash = crypto.createHash( macConfig.keyHashAlgorithm );
        keyHash.update( key );

        let keyDigest = keyHash.digest();
        hmac = crypto.createHmac( macConfig.macAlgorithm, keyDigest );
        hmac.update( salt );
        hmac.update( encrypted );

        let mac = hmac.digest();
        if ( features.log ) {
            console.error( "ENCRYPT-MAC: salt: ", salt );
            console.error( "ENCRYPT-MAC: mac: ", mac );
        }
        let result = Buffer.alloc( salt.length + mac.length + encrypted.length );
        salt.copy( result );
        mac.copy( result, salt.length );
        encrypted.copy( result, salt.length + mac.length );
        return result;
    }

    const _encrypt = ( data ) => {
        const iv = newInitializationVector( cryptoConfig );
        var buf = data;
        if ( features.log ) {
            console.error( "ENC: iv: ", iv );
        }
        for ( var i = 0; i < cryptoConfig.rounds; i++ ) {
            let cipher = crypto.createCipheriv( cryptoConfig.algorithm, key, iv );
            cipher.setAutoPadding( true );
            let firstBuf = cipher.update( buf );
            let secondBuf = cipher.final( );
            buf = Buffer.alloc( firstBuf.length + secondBuf.length + cryptoConfig.ivSize );
            firstBuf.copy( buf, cryptoConfig.ivSize );
            secondBuf.copy( buf, firstBuf.length + cryptoConfig.ivSize );
            iv.copy( buf );
        }
        if ( features.log ) {
            console.error( 'ENC: payload-length:', buf.length - iv.length )
        }
        return buf;
    }

    /**
     * Decrypt a buffer or Base64 string and parse it as JSON.
     * 
     * @param {String|Buffer} buffer
     * @returns {Array|Object}
     */
    this.decryptToObject = ( buffer ) => {
        return JSON.parse( this.decryptString( buffer ) );
    }

    /**
     * Get the minimum length a buffer must have in order to have something
     * to decrypt in it.
     * 
     * @returns {PortableCrypto.minDecryptableLength.result|@var;cryptoConfig.ivSize|type.ivSize|@var;AES128.ivSize}
     */
    this.minDecryptableLength = () => {
        let result = cryptoConfig.ivSize;
        if ( features.mac ) {
            result += macConfig.macLength + macConfig.saltLength;
        }
        return result;
    }

    /**
     * Decrypt a buffer or base64 string.
     * 
     * @param {type} buffer
     * @returns {PortableCrypto._decrypt.buffer|Error|err}
     */
    this.decrypt = ( buffer ) => {
        if ( typeof buffer === 'string' ) {
            buffer = Buffer.from( buffer, 'base64' );
        }
        if ( !features.mac ) {
            if (!features.encrypt) {
                return buffer;
            }
            let iv = buffer.slice( 0, cryptoConfig.ivSize );
            let payloadData = buffer.slice( cryptoConfig.ivSize );
            return _decrypt( iv, payloadData );
        }
        let salt = buffer.slice( 0, macConfig.saltLength );
        let timestamp = read64bit( salt, 0 ) + TIMESTAMP_BASE;
        let now = new Date().getTime();
        let timestampValid = now + ONE_DAY_MILLIS > timestamp && timestamp > TIMESTAMP_BASE;
        if ( features.log ) {
            console.error( 'DECRYPT-MAC: salt:', salt )
            console.error( 'DECRYPT-MAC: salt-timestamp:', timestamp + " - " + new Date( timestamp )
                    + " " + (timestampValid ? "valid" : "invalid") )
        }
        if ( !timestampValid ) {
            throw new Error( "Illegal timestamp in salt" );
        }

        let mac = buffer.slice( macConfig.saltLength, macConfig.saltLength + macConfig.macLength );
        let iv = buffer.slice( macConfig.saltLength + macConfig.macLength, macConfig.saltLength + macConfig.macLength + cryptoConfig.ivSize );
        let toDecrypt = buffer.slice( macConfig.saltLength + macConfig.macLength + cryptoConfig.ivSize );

        let keyHash = crypto.createHash( macConfig.keyHashAlgorithm );
        keyHash.update( key );
        let keyDigest = keyHash.digest();
        hmac = crypto.createHmac( macConfig.macAlgorithm, keyDigest );
        hmac.update( salt );
        hmac.update( iv )
        hmac.update( toDecrypt );
        let computedMac = hmac.digest();

        if ( features.log ) {
            console.error( 'DECRYPT-MAC: iv: ', iv )
            console.error( 'DECRYPT-MAC: mac-received: ', mac )
            console.error( 'DECRYPT-MAC: mac-computed: ', computedMac )
            console.error( 'DECRYPT-MAC: key-hash:', keyDigest )
        }
        let macValidated = computedMac.equals( mac );
        if ( features.log ) {
            console.error( 'DECRYPT-MAC: ' + (macValidated ? "valid" : "invalid") );
        }
        if ( !macValidated ) {
            throw new Error( "Mac does not match" );
        }
        if (!features.encrypt) {
            let result = Buffer.alloc(iv.length + toDecrypt.length);
            iv.copy(result, 0);
            toDecrypt.copy(result, iv.length);
            return result;
        }
        return _decrypt( iv, toDecrypt );
    }

    const _decrypt = ( iv, buffer ) => {
        for ( var i = 0; i < cryptoConfig.rounds; i++ ) {
            const decipher = crypto.createDecipheriv( cryptoConfig.algorithm, key, iv );
            decipher.setAutoPadding( true );
            let firstBuf = decipher.update( buffer );
            let secondBuf = decipher.final();
            buffer = Buffer.alloc( firstBuf.length + secondBuf.length );
            firstBuf.copy( buffer );
            secondBuf.copy( buffer, firstBuf.length );
        }
        return buffer;
    }

    function write64bit( num, buffer, pos ) {
        const mask = 0xFFFFFFFF;
        const msdw = ~~(num / mask)
        const lsdw = (num % mask) - msdw
        buffer.writeUInt32BE( msdw, 0 )
        buffer.writeUInt32BE( lsdw, 4 )
    }

    function read64bit( buffer, pos ) {
        let msdw = buffer.readUInt32BE( pos );
        let lsdw = buffer.readUInt32BE( pos + 4 );
        return msdw * 0x100000000 + lsdw;
    }

    function createKey( password ) {
        // Coerces the password into the available bits,
        // wrapping around and xor'ing if longer
        var key = Buffer.from( password, 'utf8' );
        let bits = (key.length * 8);
        if ( bits > cryptoConfig.keyBitLimit ) {
            var amt = cryptoConfig.keyByteLimit;
            let nue = Buffer.alloc( amt );
            for ( var i = 0; i < amt; i++ ) {
                nue.writeUInt8( key.readUInt8( i ), i );
            }
            var pos = amt;
            while ( pos < key.length ) {
                for ( let i = 0; i < nue.length && pos < key.length; i++ ) {
                    let newValue = nue.readUInt8( i ) ^ key.readUInt8( pos++ );
                    nue.writeUInt8( newValue, i );
                }
            }
            key = nue;
        }
        return key;
    }
}

function CryptoConfig( keyBitLimit, algorithm, ivSize, rounds ) {
    if ( keyBitLimit % 8 !== 0 ) {
        throw new Error( "Bit limit not divisible by 8:" + keyBitLimit );
    }
    this.keyBitLimit = keyBitLimit;
    this.algorithm = algorithm;
    this.ivSize = ivSize;
    this.keyByteLimit = keyBitLimit / 8;
    this.rounds = rounds;

    this.toString = () => {
        return ["key-bits", keyBitLimit, "iv-size", ivSize, "algorithm", algorithm].join( ' ' );
    }
}

function MacConfig( saltLength, macLength, macAlgorithm, keyHashAlgorithm ) {
    this.saltLength = saltLength;
    this.macLength = macLength;
    this.macAlgorithm = macAlgorithm;
    this.keyHashAlgorithm = keyHashAlgorithm;

    this.toString = () => {
        return ["salt-length", saltLength, "mac-length", macLength,
            "mac-algorithm", macAlgorithm, "key-hash-algorithm", keyHashAlgorithm].join( ' ' );
    }
}

function Features() {
    if ( arguments.length === 1 && typeof arguments[0] === 'object' ) {
        arguments = Object.keys( arguments[0] );
    }
    for ( var i = 0; i < arguments.length; i++ ) {
        if ( arguments[i] ) {
            switch ( arguments[i] ) {
                case FEATURE_DETERMINISTIC_TEST_MODE :
                case FEATURE_LOG:
                case FEATURE_ENCRYPT:
                case FEATURE_USE_MAC :
                    break;
                default :
                    throw new Error( "Unknown feature " + arguments[i]
                            + ". Available features are: "
                            + [FEATURE_USE_MAC, FEATURE_LOG,
                                FEATURE_DETERMINISTIC_TEST_MODE].join( ', ' ) );
            }
            this[arguments[i]] = true;
        }
    }

    this.toString = () => {
        let result = [];
        for ( var key in this ) {
            if ( typeof this[key] === 'boolean' ) {
                result.push( key );
            }
        }
        return result.join( ' ' );
    }
}

if ( require.main === module ) {
    function printHelpAndExit( msg ) {
        console.log( 'Error: ' + msg + '\n' )
        console.log( 'Usage: portable-crypto --passphrase "iHazSekurity" '
                + ' --log --aes --in somefile.txt --out encryptedfile.b64' );
        console.log( '\nOPTIONS:\n' );
        console.log( ' -d | --decrypt - Decrypt instead of encrypt' )
        console.log( ' -a | --aes     - Use AES128 encryption instead of Blowfish' )
        console.log( ' -c | --noencrypt   - Don\'t encrypt or decrypt, just validate the mac' )
        console.log( ' -n | --nomac   - Don\'t generate an hmac to verify message integrity' )
        console.log( ' -p | --pass    - Use the passed password or passphrase' )
        console.log( ' -e | --passenv - Read the passphrase from an environment variable' )
        console.log( ' -v | --verbose - Log buffer contents for debugging' )
        console.log( ' -i | --in      - Read input from this file instead of stdin' )
        console.log( ' -o | --out     - Write binary output to this file instead of stdout' )
        console.log( ' -6 | --base64  - If encrypting, output base64 not binary encrypted data (encrypt only); if decrypting, decode base64 input' )
        process.exit( msg ? 1 : 0 );
    }

    const cmdline = require( './cmdline' );
    const expansions = {
        a: 'aes',
        n: 'nomac',
        p: 'passphrase',
        q: 'passfile',
        e: 'passenv',
        v: 'verbose',
        i: 'in',
        o: 'out',
        d: 'decrypt',
        x: 'deterministic',
        '6': 'base64'
    };
    const args = cmdline.parseArgs( expansions );
    if ( !args.passphrase && !args.passfile && !args.passenv ) {
        printHelpAndExit( 'No passphrase, passenv environment variable name or passphrase file provided. Use -p or -e or -q.' )
    }
    var f = {};
    if ( !args.nomac ) {
        f.mac = true;
    }
    if ( !args.noencrypt ) {
        f.encrypt = true;
    }
    if ( args.verbose ) {
        f.log = true;
    }
    if ( args.deterministic ) {
        f.deterministic = true;
    }
    f = new Features( f );

    const cryptoConfig = args.aes ? AES128 : BLOWFISH;

    const fs = require( 'fs' );

    const pass = args.passenv ? process.env[args.passenv] : args.passphrase ? args.passphrase :
            fs.readFileSync( args.passfile );
    if ( !pass ) {
        printHelpAndExit( "No passphrase available - " + args.passenv + " is not set" );
    }

    if ( f.log ) {
        console.error( 'START: ' + require( 'util' ).inspect( args ) )
    }

    const pcrypt = new PortableCrypto( pass, cryptoConfig, HMAC256, f );

    function runEncrypt( input ) {
        let buf = pcrypt.encrypt( input );
        if ( args.base64 ) {
            if ( f.log ) {
                console.error( 'END: convert ' + buf.length + ' bytes of output to base64' )
            }
            buf = buf.toString( 'base64' );
        }
        if ( f.log ) {
            console.error( 'END: write ' + buf.length + ' bytes to '
                    + args.out ? args.out : '<stdout>' )
        }
        if ( args.out ) {
            fs.writeFileSync( args.out, buf );
        } else {
            process.stdout.write( buf );
        }
        process.exit( 0 );
    }

    function runDecrypt( input ) {
        if ( args.base64 ) {
            if ( f.log ) {
                console.error( 'END: convert ' + input.length + ' bytes of input from base64 to binary' )
            }
            input = Buffer.from( input.toString( 'utf8' ), 'base64' );
        }
        let buf = pcrypt.decrypt( input );
        if ( f.log ) {
            console.error( 'END: write ' + buf.length + ' bytes to '
                    + args.out ? args.out : '<stdout>' )
        }
        if ( args.out ) {
            fs.writeFileSync( args.out, buf );
        } else {
            process.stdout.write( buf );
        }
        process.exit( 0 );
    }

    function run( input ) {
        if ( args.decrypt ) {
            runDecrypt( input );
        } else {
            runEncrypt( input );
        }
    }

    if ( f.log ) {
        console.error( 'INIT: read: ' + (args.in ? args.in : '<stdin>') );
    }
    var input = args.in ? fs.readFileSync( args.in ) : null;
    if ( !input ) {
        var chunks = [];
        var length = 0;
        process.stdin.on( 'data', function ( dta ) {
            chunks.push( dta );
            length += dta.length;
        } );
        process.stdin.on( 'end', function () {
            if ( length === 0 ) {
                printHelpAndExit( "Input closed without sending any bytes" )
            }
            let buf = Buffer.alloc( length );
            let pos = 0;
            for ( let i = 0; i < chunks.length; i++ ) {
                chunks[i].copy( buf, pos );
                pos += chunks[i].length;
            }
            if ( f.log ) {
                console.error( 'INIT: read: Received ' + buf.length + " bytes of input" );
            }
            run( buf );
        } );
    } else {
        run( input );
    }
}