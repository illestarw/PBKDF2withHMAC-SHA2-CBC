/**
 * @Project PBKDF2withHMAC-SHA2-CBC
 * 
 * An extendable framework for Java encryption implementation using Password-Based Key Derivation Function #2
 * currently supporting AES / Triple DES cipher and SHA-256 / 512 HMAC algorithm under Cipher Block Chaining mode.
 * 
 */
package pbkdf2withhmacsha2cbc;

/**
 *
 * @author Illestar
 */

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.GeneralSecurityException;
import java.util.Scanner;
import pbkdf2withhmacsha2cbc.CryptoInstance.*;

/**
 * The main launcher for interactive menu.
 */
public class Launch {
    
    private static int getModule() {
        int mod = 0;
        try {
            Scanner sc = new Scanner(System.in);
            if (sc.hasNextInt()) {
                mod = sc.nextInt();
            }
            if (mod == 1 || mod == 2) {
                return mod;
            } else {
                System.err.println("Invalid number " + mod + " for module option");
                return getModule();
            }
        } catch (Exception e) {
            System.err.println("Invalid format" + e);
            return 0;
        }
    }
    
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
                    return KeyLength.BITS_128;
                case 2:
                    return KeyLength.BITS_192;
                case 3:
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
                System.err.println("Invalid number " + hmac + " for HMAC option");
                return getHMACAlgorithm();
            }
        } catch (Exception e) {
            System.err.println("Invalid format" + e);
            return 1;
        }
    }
    
    private static int getIteration() {
        int i = 1;
        try {
            Scanner sc = new Scanner(System.in);
            if (sc.hasNextInt()) {
                i = sc.nextInt();
            }
            if (i > 0)
                return i;
            else {
                System.err.println("Invalid number " + i + " for iteration (must > 0)");
                return getIteration();
            }
        } catch (Exception e) {
            System.err.println("Invalid format" + e);
            return 1;
        }
    }
    
    private static File getFileInstance() {
        File f;
        String fname = "";
        try {
            Scanner sc = new Scanner(System.in);
            if (sc.hasNextLine()) {
                fname = sc.nextLine();
            }
            Path p = Paths.get(System.getProperty("user.home"),"javaenc", fname);
            f = p.toFile();
            return f;
        } catch (Exception e) {
            System.err.println("Exception occured: " + e);
            return getFileInstance();
        }
    }
    
    public static void main(String args[]) throws GeneralSecurityException, IOException
    {
        // Init
        int hmac, iv = 0, iterate, module;
        Algorithm alg;
        KeyLength keylen;
        Pbkdf pbkdf = null;
        MacAlgorithm macalg = null;
        String pwd;
        File fin, fout;
        
        
        Scanner sc = new Scanner(System.in);
        
        // Show menu
        System.out.println("===========* PBKDF Implementation *===========");
        System.out.println("Please Select Module:");
        System.out.println("[1] Encryption [2] Decryption");
        module = getModule();
        
        if (module == 1) {
            System.out.println("============= Encryption Module =============");
            System.out.println("Select the algorithm for encryption:");
            System.out.println("[1] 3DES [2] AES");
            alg = getEncryptionAlgorithm();
            if (alg == Algorithm.DESede)
                iv = 8;
            else if (alg == Algorithm.AES)
                iv = 16;
            System.out.println("Specify the key length for encryption algorithm:");
            System.out.println("[1] 128 [2] 192 [3] 256");
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
            System.out.println("Provide a password:");
            pwd = "";
            if (sc.hasNextLine())
                pwd = sc.nextLine();

            System.out.println("Please put file under (user home directory)/javaenc in Linux or C:\\(user directory)\\javaenc in Windows.");
            System.out.println("Specify plaintext filename: ");
            fin = getFileInstance();
            System.out.println("Specify output filename: ");
            fout = getFileInstance();
        
            // Initialize new instance based on user-assigned configs
            CryptoLib cl = new CryptoLib(new CryptoInstance(alg, Mode.CBC, Padding.PKCS5_PADDING, keylen, pbkdf, macalg, iv, iterate));

            cl.encrypt(fin, fout, pwd.toCharArray());
        }
        else if (module == 2) {
            System.out.println("============= Decryption Module =============");
            System.out.println("Please put file under (user home directory)/javaenc in Linux or C:\\(user directory)\\javaenc in Windows.");
            System.out.println("Specify ciphertext filename: ");
            fin = getFileInstance();
            System.out.println("Specify output filename: ");
            fout = getFileInstance();
            System.out.println("Provide a password:");
            pwd = "";
            if (sc.hasNextLine())
                pwd = sc.nextLine();
            
            // Initialize ExtractHeader for reading cipher settings
            ExtractHeader eh = new ExtractHeader();

            //debug: auto-test
            // Path p = Paths.get(System.getProperty("user.home"),"javaenc", fin.getName() + "_reverse.txt");
            // File fin2 = p.toFile();
            
            // parse configuration and build CryptoLib instance
            CryptoLib cl2 = eh.parse(fin);
            
            cl2.decrypt(fin, fout, pwd.toCharArray());
        }
        
        System.out.println("\n Process Succeeded.");
        
    }
    
}