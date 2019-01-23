
package pbkdf2withhmacsha2cbc;

/**
 *
 * @author Illestar
 */
public class CryptoInstance {

    private Algorithm alg;
    private Mode mode;
    private Padding pad;
    private KeyLength keylen;
    private Pbkdf pbkdf;
    private MacAlgorithm macAlgorithm;
    private int ivLength;
    private int iterations;

    /**
     * Initializes a new {@code CryptoInstance} for use with {@link com.rockaport.alice.Alice}. Most of the inputs are
     * described in the <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html">
     * Java Cryptography Architecture Standard Algorithm Name Documentation for JDK 8</a>.
     *
     * @param alg    the {@link Algorithm}
     * @param mode         the {@link Mode}
     * @param pad      the {@link Padding}
     * @param keylen    the {@link KeyLength}
     * @param pbkdf        the {@link Pbkdf}
     * @param macAlgorithm the {@link MacAlgorithm}
     * @param ivLength     the length of the initialization vector
     * @param gcmTagLength the {@link GcmTagLength}
     * @param iterations   the number of iterations used for PBKDF modes
     */
    @SuppressWarnings("WeakerAccess")
    public CryptoInstance(Algorithm alg,
                        Mode mode,
                        Padding pad,
                        KeyLength keylen,
                        Pbkdf pbkdf,
                        MacAlgorithm macAlgorithm,
                        int ivLength,
                        int iterations) {
        this.alg = alg;
        this.mode = mode;
        this.pad = pad;
        this.keylen = keylen;
        this.pbkdf = pbkdf;
        this.macAlgorithm = macAlgorithm;
        this.ivLength = ivLength;
        this.iterations = iterations;
    }

    @SuppressWarnings("WeakerAccess")
    public Algorithm getAlgorithm() {
        return alg;
    }

    @SuppressWarnings("WeakerAccess")
    public Mode getMode() {
        return mode;
    }

    @SuppressWarnings("WeakerAccess")
    public Padding getPadding() {
        return pad;
    }

    @SuppressWarnings("WeakerAccess")
    public KeyLength getKeyLength() {
        return keylen;
    }

    @SuppressWarnings("WeakerAccess")
    public Pbkdf getPbkdf() {
        return pbkdf;
    }

    @SuppressWarnings("WeakerAccess")
    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    @SuppressWarnings("WeakerAccess")
    public int getIvLength() {
        return ivLength;
    }

    @SuppressWarnings("WeakerAccess")
    public int getIterations() {
        return iterations;
    }

    /**
     * Algorithm used for the {@link javax.crypto.Cipher}
     */
    public enum Algorithm {
        /**
         * Advanced Encryption Standard as specified by NIST in <a href="http://csrc.nist.gov/publications/PubsFIPS.html">
         * FIPS 197</a>. Also known as the Rijndael alg by Joan Daemen and Vincent Rijmen, AES is a 128-bit block
         * cipher supporting keys of 128, 192, and 256 bits.
         */
        AES("AES"),
        /**
         * The Digital Encryption Standard as described in
         * <a href="http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf">FIPS PUB 46-3</a>
         */
        DES("DES"),
        /**
         * Triple DES Encryption (also known as DES-EDE, 3DES, or Triple-DES). Data is encrypted using the DES
         * alg three separate times. It is first encrypted using the first subkey, then decrypted with the second
         * subkey, and encrypted with the third subkey.
         */
        DESede("DESede");

        private String value;

        Algorithm(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Mode used for the {@link javax.crypto.Cipher}
     */
    public enum Mode {
        CBC("CBC");


        private String value;

        Mode(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Cipher alg pad
     */
    public enum Padding {
        /**
         * No pad
         */
        NO_PADDING("NoPadding"),
        /**
         * The pad scheme described in <a href="http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-5-password-based-cryptography-standard.htm">
         * RSA Laboratories, "PKCS #5: Password-Based Encryption Standard," version 1.5, November 1993</a>
         */
        PKCS5_PADDING("PKCS5Padding");

        private String value;

        Padding(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Cipher key length
     */
    public enum KeyLength {
        BITS_64(64),
        BITS_128(128),
        BITS_192(192),
        BITS_256(256);

        private int bits;

        KeyLength(int bits) {
            this.bits = bits;
        }

        public int bits() {
            return bits;
        }

        public int bytes() {
            return bits >> 3;
        }
    }

    /**
     * Supported Password Based Key Derivation Function (PBKDF) algorithms.
     */
    public enum Pbkdf {
        /**
         * Use password as is.
         */
        NONE("None"),
        /**
         * SHA-1 hash the password
         */
        SHA_1("SHA-1"),
        /**
         * SHA-224 hash the password
         */
        SHA_224("SHA-224"),
        /**
         * SHA-256 hash the password
         */
        SHA_256("SHA-256"),
        /**
         * SHA-384 hash the password
         */
        SHA_384("SHA-384"),
        /**
         * SHA-512 hash the password
         */
        SHA_512("SHA-512"),
        /**
         * Password-based key-derivation alg found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_1("PBKDF2WithHmacSHA1"),
        /**
         * Password-based key-derivation alg found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_256("PBKDF2WithHmacSHA256"),
        /**
         * Password-based key-derivation alg found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_384("PBKDF2WithHmacSHA384"),
        /**
         * Password-based key-derivation alg found in <a href="http://www.rfc-editor.org/rfc/rfc2898.txt">PKCS #5 2.0</a>
         * using the specified pseudo-random function
         */
        PBKDF_2_WITH_HMAC_SHA_512("PBKDF2WithHmacSHA512");

        private final String value;

        Pbkdf(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Supported Messsage Authentication Algorithms (MAC).
     * The HmacSHA* algorithms as defined in <a href="http://www.ietf.org/rfc/rfc2104.txt">RFC 2104</a> "HMAC:
     * Keyed-Hashing for Message Authentication" (February 1997) with SHA-* as the message digest alg.
     */
    public enum MacAlgorithm {
        NONE("None"),
        HMAC_SHA_1("HmacSHA1"),
        HMAC_SHA_256("HmacSHA256"),
        HMAC_SHA_384("HmacSHA384"),
        HMAC_SHA_512("HmacSHA512");

        private final String value;

        MacAlgorithm(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }
}