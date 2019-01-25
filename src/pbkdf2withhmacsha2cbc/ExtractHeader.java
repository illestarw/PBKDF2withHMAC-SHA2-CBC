/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pbkdf2withhmacsha2cbc;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author Illestar
 */
public class ExtractHeader {
    public synchronized CryptoLib parse(File input) throws IOException {
        if (input == null || !input.exists() || input.length() <= 0) {
            throw new IllegalArgumentException("Input file is either null or does not exist");
        }

        BufferedInputStream bufferedInputStream = null;

        // setup streams
        bufferedInputStream = new BufferedInputStream(new FileInputStream(input));

        // read configs from header (size = 16)
        byte[] headerBytes = new byte[16];

        int headerBytesRead = bufferedInputStream.read(headerBytes);

        if (headerBytesRead < 16) {
            throw new IOException("File doesn't contain information for decryption");
        }

        String headerString = new String(headerBytes, StandardCharsets.UTF_8);
        
        System.out.println(headerString);

        // parse configs (encryption alg || keylen || hmackeylen || iteration) to CryptoInstance
        CryptoInstanceSetter cis = new CryptoInstanceSetter();
        
        if (headerString.charAt(0) == 'A') {
            cis.setAlgorithm(CryptoInstance.Algorithm.AES);
            cis.setIvLength(16);
        } else if (headerString.charAt(0) == 'D') {
            cis.setAlgorithm(CryptoInstance.Algorithm.DESede);
            cis.setIvLength(8);
        }

        if (Integer.parseInt(headerString.substring(1, 4)) == 128) cis.setKeyLength(CryptoInstance.KeyLength.BITS_128);
        else if (Integer.parseInt(headerString.substring(1, 4)) == 192) cis.setKeyLength(CryptoInstance.KeyLength.BITS_192);
        else if (Integer.parseInt(headerString.substring(1, 4)) == 256) cis.setKeyLength(CryptoInstance.KeyLength.BITS_256);

        if (Integer.parseInt(headerString.substring(4, 7)) == 256) {
            cis.setPbkdf(CryptoInstance.Pbkdf.PBKDF_2_WITH_HMAC_SHA_256);
            cis.setMacAlgorithm(CryptoInstance.MacAlgorithm.HMAC_SHA_256);
        } else if (Integer.parseInt(headerString.substring(4, 7)) == 512) {
            cis.setPbkdf(CryptoInstance.Pbkdf.PBKDF_2_WITH_HMAC_SHA_512);
            cis.setMacAlgorithm(CryptoInstance.MacAlgorithm.HMAC_SHA_512);
        }

        cis.setIterations(Integer.parseInt(headerString.substring(headerString.length() - 9)));
        
        return new CryptoLib(cis.build());
    }
}
    
