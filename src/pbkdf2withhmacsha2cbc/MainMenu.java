
package pbkdf2withhmacsha2cbc;

import java.security.Security;
import java.util.Scanner;
/**
 *
 * @author Illestar
 */
public class MainMenu {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        String password = "";
        int enc_mode = 0;
        
        
        // Debug: check Bouncy Castle provider;
        if (Security.getProvider("BC") == null) {
            System.out.println("Bouncy Castle provider is NOT available");
        } else {
            System.out.println("Bouncy Castle provider is available");
        }
        
        Scanner sc = new Scanner(System.in);
        System.out.println("Select encryption mode: ");
        enc_mode = sc.nextInt();
        
        System.out.println("Provide a password: ");
        password = sc.next();
        
        byte[] pwd = password.getBytes();
        
        
        
        // close scanner 
        sc.close();
        
        
    }
    
}
