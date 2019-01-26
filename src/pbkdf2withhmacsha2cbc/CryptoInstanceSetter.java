
package pbkdf2withhmacsha2cbc;

/**
 *
 * @author Illestar
 */

import pbkdf2withhmacsha2cbc.CryptoInstance.*;

public class CryptoInstanceSetter {

    /**
     * The setter class with parameters initialized for building a CryptoInstance.
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
    
    private Algorithm algorithm = null;
    private Mode mode = Mode.CBC;
    private Padding padding = Padding.PKCS5_PADDING;
    private KeyLength keyLength = null;
    private Pbkdf pbkdf = null;
    private MacAlgorithm macAlgorithm = null;
    private int ivLength = 16;
    private int iterations = 10000;

    public CryptoInstanceSetter setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public CryptoInstanceSetter setMode(Mode mode) {
        this.mode = mode;
        return this;
    }

    public CryptoInstanceSetter setPadding(Padding padding) {
        this.padding = padding;
        return this;
    }

    public CryptoInstanceSetter setKeyLength(KeyLength keyLength) {
        this.keyLength = keyLength;
        return this;
    }

    public CryptoInstanceSetter setPbkdf(Pbkdf pbkdf) {
        this.pbkdf = pbkdf;
        return this;
    }

    public CryptoInstanceSetter setMacAlgorithm(MacAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
        return this;
    }

    public CryptoInstanceSetter setIvLength(int ivLength) {
        this.ivLength = ivLength;
        return this;
    }

    public CryptoInstanceSetter setIterations(int iterations) {
        this.iterations = iterations;
        return this;
    }

    public CryptoInstance build() {
        return new CryptoInstance(algorithm, mode, padding, keyLength, pbkdf, macAlgorithm, ivLength, iterations);
    }
}