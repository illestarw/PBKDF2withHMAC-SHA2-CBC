
package pbkdf2withhmacsha2cbc;


public class CryptoInstance {

    private Algorithm algorithm;
    private Mode mode;
    private Padding padding;
    private KeyLength keyLength;
    private Pbkdf pbkdf;
    private MacAlgorithm macAlgorithm;
    private int ivLength;
    private int iterations;

    /**
     * An extendable Crypto configuration instance for the encryption and decryption in CryptoLib class.
     * 
     * @param algorithm         the encryption algorithm
     * @param mode              the encryption mode
     * @param padding           the padding method
     * @param keyLength         the key length for encryption
     * @param pbkdf             the PBKDF mode
     * @param macAlgorithm      the MAC algorithm
     * @param ivLength          the length of the initialization vector (byte) // i.e. bit / 8
     * @param iterations        the number of iterations used for PBKDF modes
     */
    
    @SuppressWarnings("WeakerAccess")
    public CryptoInstance(Algorithm algorithm,
                        Mode mode,
                        Padding padding,
                        KeyLength keyLength,
                        Pbkdf pbkdf,
                        MacAlgorithm macAlgorithm,
                        int ivLength,
                        int iterations) {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
        this.keyLength = keyLength;
        this.pbkdf = pbkdf;
        this.macAlgorithm = macAlgorithm;
        this.ivLength = ivLength;
        this.iterations = iterations;
    }

    @SuppressWarnings("WeakerAccess")
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    @SuppressWarnings("WeakerAccess")
    public Mode getMode() {
        return mode;
    }

    @SuppressWarnings("WeakerAccess")
    public Padding getPadding() {
        return padding;
    }

    @SuppressWarnings("WeakerAccess")
    public KeyLength getKeyLength() {
        return keyLength;
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
     * Algorithm used for javax.crypto.Cipher class.
     */
    public enum Algorithm {
        AES("AES"),
        DESede("DESede");

        /*
        DESede("DESede", "01");
        AES("AES", "02"),
        */
        private String value;
        private String headerCode;
        
        Algorithm(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }

    /**
     * Mode used for the javax.crypto.Cipher (currently support CBC only).
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
     * Cipher algorithm padding.
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
     * Cipher key length.
     */
    public enum KeyLength {
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