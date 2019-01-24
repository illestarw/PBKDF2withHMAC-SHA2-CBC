/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pbkdf2withhmacsha2cbc;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Scanner;
import pbkdf2withhmacsha2cbc.CryptoInstance.*;
/**
 *
 * @author Illestar
 */

public class Launch {
    
    private static Algorithm getEncryptionAlgorithm() {
        int alg = 0;
        try {
            Scanner sc = new Scanner(System.in);
            if (sc.hasNextInt()) {
                alg = sc.nextInt();
            }
            if (alg == 1) {
                // 3DES
                return Algorithm.DESede;
            } else if (alg == 2) {
                // AES
                return Algorithm.AES;
            } else {
                System.err.println("Invalid number " + alg + " for algorithm option");
                return getEncryptionAlgorithm();
            }
        } catch (Exception e) {
            System.err.println("Invalid format" + e);
            return null;
        }
    }
    
    private static KeyLength getEncryptionKeyLen() {
        int keylen = 0;
        try {
            Scanner sc = new Scanner(System.in);
            if (sc.hasNextInt()) {
                keylen = sc.nextInt();
            }
            switch(keylen) {
                case 1:
                    return KeyLength.BITS_64;
                case 2:
                    return KeyLength.BITS_128;
                case 3:
                    return KeyLength.BITS_192;
                case 4:
                    return KeyLength.BITS_256;
                default:
                    System.err.println("Invalid number " + keylen + " for key length option");
                    return getEncryptionKeyLen();
            }
        } catch (Exception e) {
            System.err.println("Invalid format" + e);
            return null;
        }
    }
    
    private static int getHMACAlgorithm() {
        int hmac = 0;
        try {
            Scanner sc = new Scanner(System.in);
            if (sc.hasNextInt()) {
                hmac = sc.nextInt();
            }
            if (hmac == 1 || hmac == 2)
                return hmac;
            else {
                System.err.println("Invalid format");
                return getHMACAlgorithm();
            }
        } catch (Exception e) {
            System.err.println("Invalid format" + e);
            return getHMACAlgorithm();
        }
    }
    
    private static int getIteration() {
        int i;
        try {
            Scanner sc = new Scanner(System.in);
            i = sc.nextInt();
            if (i > 0)
                return i;
            else {
                System.err.println("Invalid format");
                return getIteration();
            }
        } catch (Exception e) {
            System.err.println("Invalid format" + e);
            return getIteration();
        }
    }
    
    public static void main(String args[]) throws GeneralSecurityException, IOException
    {
        // Init
        int hmac, iv = 0, iterate;
        Algorithm alg;
        KeyLength keylen;
        Pbkdf pbkdf = null;
        MacAlgorithm macalg = null;

        // Show menu
        System.out.println("============= Encryption Module =============");
        System.out.println("Select the algorithm for encryption:");
        System.out.println("[1] 3DES [2] AES");
        alg = getEncryptionAlgorithm();
        if (alg == Algorithm.DESede)
            iv = 8;
        else if (alg == Algorithm.AES)
            iv = 16;
        System.out.println("Specify the key length for encryption algorithm:");
        System.out.println("[1] 64 [2] 128 [3] 192 [4] 256");
        keylen = getEncryptionKeyLen();
        System.out.println("Select the HMAC algorithm:");
        System.out.println("[1] SHA256 [2] SHA512");
        hmac = getHMACAlgorithm();
        if (hmac == 1) {
            pbkdf = Pbkdf.PBKDF_2_WITH_HMAC_SHA_256;
            macalg = MacAlgorithm.HMAC_SHA_256;
        } else if (hmac == 2) {
            pbkdf = Pbkdf.PBKDF_2_WITH_HMAC_SHA_512;
            macalg = MacAlgorithm.HMAC_SHA_512;
        }
        System.out.println("Assign number of iterations:");
        iterate = getIteration();
        
        
        CryptoLib cl = new CryptoLib(new CryptoInstance(alg, Mode.CBC, Padding.PKCS5_PADDING, keylen, pbkdf, macalg, iv, iterate));

        byte[] encrypted = cl.encrypt("in".getBytes(), "pass".toCharArray());

        for(byte b : encrypted){
            System.out.print(b);
        }
        System.out.println();
        
    }
    
}


