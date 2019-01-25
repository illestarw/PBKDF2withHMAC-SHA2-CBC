
package pbkdf2withhmacsha2cbc;


public class CryptoInstance {

    private Algorithm alg;
    private Mode mode;
    private Padding pad;
    private KeyLength keylen;
    private Pbkdf pbkdf;
    private MacAlgorithm macalg;
    private int ivLength;
    private int iterations;

    /**
     * @param alg           the encryption algorithm
     * @param mode          the encryption mode
     * @param pad           the padding method
     * @param keylen        the key length for encryption
     * @param pbkdf         the PBKDF mode
     * @param macalg        the MAC algorithm
     * @param ivLength      the length of the initialization vector (byte) // i.e. bit / 8
     * @param iterations    the number of iterations used for PBKDF modes
     */
    @SuppressWarnings("WeakerAccess")
    public CryptoInstance(Algorithm alg,
                        Mode mode,
                        Padding pad,
                        KeyLength keylen,
                        Pbkdf pbkdf,
                        MacAlgorithm macalg,
                        int ivLength,
                        int iterations) {
        this.alg = alg;
        this.mode = mode;
        this.pad = pad;
        this.keylen = keylen;
        this.pbkdf = pbkdf;
        this.macalg = macalg;
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
        return macalg;
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
     * Algorithm used for javax.crypto.Cipher
     */
    public enum Algorithm {
        AES("AES"),
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
     * Mode used for the javax.crypto.Cipher
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
     * Cipher algorithm padding
     */
    public enum Padding {
        NO_PADDING("NoPadding"),
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
         * Use password as it is.
         */
        NONE("None"),

        PBKDF_2_WITH_HMAC_SHA_256("PBKDF2WithHmacSHA256"),

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
     * Messsage Authentication Algorithms (MAC).
     */
    public enum MacAlgorithm {
        NONE("None"),
        HMAC_SHA_256("HmacSHA256"),
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