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
public class Launch {
    
    public static void main(String args[])
    {
        CryptoLib cl = new CryptoLib(new CryptoInstance(CryptoInstance.Algorithm.AES, CryptoInstance.Mode.CBC, CryptoInstance.Padding.PKCS5_PADDING, CryptoInstance.KeyLength.BITS_256, CryptoInstance.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512, CryptoInstance.MacAlgorithm.HMAC_SHA_512, 16, 1));
        
    }
    
}
