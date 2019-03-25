/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pbkdf2withhmacsha2cbc;

/**
 *
 * @author Illestar
 */
public class Header {

    /**
     * An dedicated class for translating between Crypto configuration instance and Header string.
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
    
    public Header(CryptoInstance c) {
        // c.getAlgorithm()
    }

    
    /*
    if (headerString.charAt(0) == 'A') {
            cis.setAlgorithm(CryptoInstance.Algorithm.AES);
            cis.setIvLength(16);
        } else if (headerString.charAt(0) == 'D') {
            cis.setAlgorithm(CryptoInstance.Algorithm.DESede);
            cis.setIvLength(8);
        } else {
            throw new IllegalArgumentException("Input file is not a valid file encrypted by this program.");
        }

        if (Integer.parseInt(headerString.substring(1, 4)) == 128) cis.setKeyLength(CryptoInstance.KeyLength.BITS_128);
        else if (Integer.parseInt(headerString.substring(1, 4)) == 192) cis.setKeyLength(CryptoInstance.KeyLength.BITS_192);
        else if (Integer.parseInt(headerString.substring(1, 4)) == 256) cis.setKeyLength(CryptoInstance.KeyLength.BITS_256);
        else {
            throw new IllegalArgumentException("Input file is not a valid file encrypted by this program.");
        }
        
        if (Integer.parseInt(headerString.substring(4, 7)) == 256) {
            cis.setPbkdf(CryptoInstance.Pbkdf.PBKDF_2_WITH_HMAC_SHA_256);
            cis.setMacAlgorithm(CryptoInstance.MacAlgorithm.HMAC_SHA_256);
        } else if (Integer.parseInt(headerString.substring(4, 7)) == 512) {
            cis.setPbkdf(CryptoInstance.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512);
            cis.setMacAlgorithm(CryptoInstance.MacAlgorithm.HMAC_SHA_512);
        } else {
            throw new IllegalArgumentException("Input file is not a valid file encrypted by this program.");
        }

        cis.setIterations(Integer.parseInt(headerString.substring(headerString.length() - 9)));
    */
}
