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
        CryptoLib cl = new CryptoLib(new CryptoInstance(algorithm, mode, padding, keyLength, pbkdf, macAlgorithm, ivLength, iterations));
    }
    
}
