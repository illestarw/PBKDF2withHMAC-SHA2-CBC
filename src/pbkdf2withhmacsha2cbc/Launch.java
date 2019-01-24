/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pbkdf2withhmacsha2cbc;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Scanner;

/**
 *
 * @author Illestar
 */
public class Launch {
    
    public static void main(String args[]) throws GeneralSecurityException, IOException
    {
        // Init
        
        
        Scanner sc = new Scanner(System.in);
        
        while(true)
        {
            // Show menu
            System.out.println("============= Encryption Module =============");
            System.out.println("Select the algorithm for encryption:");
            
            
            CryptoLib cl = new CryptoLib(new CryptoInstance(CryptoInstance.Algorithm.AES, CryptoInstance.Mode.CBC, CryptoInstance.Padding.PKCS5_PADDING, CryptoInstance.KeyLength.BITS_256, CryptoInstance.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512, CryptoInstance.MacAlgorithm.HMAC_SHA_512, 16, 1));

        
        
            byte[] encrypted = cl.encrypt("in".getBytes(), "pass".toCharArray());

            for(byte b : encrypted){
                System.out.print(b);
            }
            System.out.println();
        }
        
    }
    
}
