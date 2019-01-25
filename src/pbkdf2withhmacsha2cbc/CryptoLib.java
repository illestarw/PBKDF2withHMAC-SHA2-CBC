
package pbkdf2withhmacsha2cbc;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


public class CryptoLib {
    private final CryptoInstance config;
    private final Cipher cipher;

    @SuppressWarnings("WeakerAccess")
    public CryptoLib(CryptoInstance config) {
        if (config == null ||
                config.getAlgorithm() == null ||
                config.getMode() == null ||
                config.getPadding() == null ||
                config.getKeyLength() == null ||
                config.getPbkdf() == null ||
                config.getMacAlgorithm() == null) {

            throw new IllegalArgumentException("Context, algorithm, mode, or padding is null");
        }

        // Algorithm/mode specific validation
        switch (config.getAlgorithm()) {
            case AES:
                switch (config.getMode()) {
                    case CBC:
                        if (config.getIvLength() != 16) {
                            throw new IllegalArgumentException("AES-CBC is selected but the IV length is not 16");
                        }
                        break;
                }
                break;
            case DESede:
                if (config.getIvLength() != 8) {
                    throw new IllegalArgumentException("3DES algorithm is selected but the IV length is not 8 " +
                            "(" + config.getIvLength() + ")");
                }
                break;
        }

        // PBKDF iterations validation
        switch (config.getPbkdf()) {
            case PBKDF_2_WITH_HMAC_SHA_256:
            case PBKDF_2_WITH_HMAC_SHA_512:
                if (config.getIterations() <= 0) {
                    throw new IllegalArgumentException("PBKDF is selected, but the number of iterations is invalid");
                }
                break;
        }

        this.config = config;

        try {
            cipher = Cipher.getInstance(config.getAlgorithm() + "/" + config.getMode() + "/" + config.getPadding());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * Generates an AES or 3DES key
     *
     * @param algorithm the key will be used with
     * @param keyLength length of key
     * @return a byte array
     * @throws GeneralSecurityException if either initialization or generation fails
     */
    @SuppressWarnings("WeakerAccess")
    public static byte[] generateKey(CryptoInstance.Algorithm algorithm, CryptoInstance.KeyLength keyLength)
            throws GeneralSecurityException {
        if (algorithm == null || keyLength == null) {
            throw new IllegalArgumentException("Algorithm or key length is null");
        }

        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm.toString());

        int actualKeyLength = keyLength.bits();

        keyGenerator.init(actualKeyLength);

        return keyGenerator.generateKey().getEncoded();
    }

    /**
     * Performs a narrowing byte-to-char conversion
     *
     * @param chars input
     * @return byte conversion
     */
    private static byte[] toBytes(char[] chars) {
        byte[] bytes = new byte[chars.length];

        for (int i = 0; i < chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    /**
     * Gets a javax.crypto.Mac instance
     *
     * @param macAlgorithm 
     * @param password     a password
     * @return an initialized javax.crypto.Mac
     * @throws GeneralSecurityException if MAC initialization fails
     */
    private Mac getMac(CryptoInstance.MacAlgorithm macAlgorithm, char[] password) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(macAlgorithm.toString());
        
        // generate the initialization vector
        byte[] initializationVector = generateInitializationVector();
        
        mac.init(deriveKey(password, initializationVector));
        // mac.init(new SecretKeySpec(toBytes(password), macAlgorithm.toString()));

        return mac;
    }

    /**
     * Encrypts a byte array using the supplied password  (not applicable yet)
     *
     * @param input    the byte array input
     * @param password the password
     * @return an encrypted byte array
     * @throws GeneralSecurityException if initialization or encryption fails
     * @throws IOException if there's a problem constructing the result
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized byte[] encrypt(byte[] input, char[] password) throws GeneralSecurityException, IOException {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input is either null or empty");
        }

        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password is either null or empty");
        }

        // generate the initialization vector
        byte[] initializationVector = generateInitializationVector();

        // initialize the cipher
        cipher.init(Cipher.ENCRYPT_MODE,
                deriveKey(password, initializationVector),
                getAlgorithmParameterSpec(config.getMode(), initializationVector));

        // encrypt
        byte[] encryptedBytes = cipher.doFinal(input);

        // construct the output (IV || CIPHER)
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        output.write(cipher.getIV());
        output.write(encryptedBytes);

        // compute the MAC and append the MAC (IV || CIPHER || MAC)
        if (config.getMacAlgorithm() != CryptoInstance.MacAlgorithm.NONE) {
            output.write(getMac(config.getMacAlgorithm(), password).doFinal(encryptedBytes));
        }

        return output.toByteArray();
    }

    /**
     * Encrypts the input file using the supplied password
     *
     * @param input    the input file
     * @param output   the output file
     * @param password the password
     * @throws GeneralSecurityException if initialization or encryption fails
     * @throws IOException              if there's a failure to read/write from/to the input/output file
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized void encrypt(File input, File output, char[] password)
            throws GeneralSecurityException, IOException {
        if (input == null || !input.exists() || input.length() <= 0) {
            throw new IllegalArgumentException("Input file is either null or does not exist");
        }

        if (output == null) {
            throw new IllegalArgumentException("Output file is null");
        }

        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password is either null or empty");
        }

        BufferedInputStream bufferedInputStream = null;
        BufferedOutputStream bufferedOutputStream = null;

        try {
            // generate the initialization vector
            byte[] initializationVector = generateInitializationVector();

            // initialize the cipher
            cipher.init(Cipher.ENCRYPT_MODE,
                    deriveKey(password, initializationVector),
                    getAlgorithmParameterSpec(config.getMode(), initializationVector));

            // initialize the mac
            Mac mac = null;

            if (config.getMacAlgorithm() != CryptoInstance.MacAlgorithm.NONE) {
                mac = getMac(config.getMacAlgorithm(), password);
            }

            // allocate variables
            int bytesRead;
            byte[] encryptedBytes;
            byte[] inputStreamBuffer = new byte[4096];

            // setup streams
            bufferedInputStream = new BufferedInputStream(new FileInputStream(input));
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(output));

            // write the initialization vector
            bufferedOutputStream.write(initializationVector);

            while ((bytesRead = bufferedInputStream.read(inputStreamBuffer)) > 0) {
                // encrypt
                encryptedBytes = cipher.update(inputStreamBuffer, 0, bytesRead);

                bufferedOutputStream.write(encryptedBytes);

                // compute the mac
                if (mac != null) {
                    mac.update(encryptedBytes);
                }
            }

            // finalize and write the cipher
            byte[] finaleEncryptedBytes = cipher.doFinal();

            bufferedOutputStream.write(finaleEncryptedBytes);

            // write the mac
            if (mac != null) {
                bufferedOutputStream.write(mac.doFinal(finaleEncryptedBytes));
            }
            
            // set metadata
            FileStore store = Files.getFileStore(output.toPath());
            if (!store.supportsFileAttributeView(UserDefinedFileAttributeView.class))
                System.err.format("UserDefinedFileAttributeView not supported on %s\n", store);
        
            UserDefinedFileAttributeView view = Files.getFileAttributeView(output.toPath(), UserDefinedFileAttributeView.class);
 
            view.write("alg", Charset.defaultCharset().encode(config.getAlgorithm().toString()));
            view.write("keylen", Charset.defaultCharset().encode(config.getKeyLength().toString()));
            view.write("pbkdf", Charset.defaultCharset().encode(config.getPbkdf().toString()));
            view.write("macalg", Charset.defaultCharset().encode(config.getMacAlgorithm().toString()));
            view.write("iv", Charset.defaultCharset().encode(String.valueOf(config.getIvLength())));
            view.write("iterate", Charset.defaultCharset().encode(String.valueOf(config.getIterations())));
            
            
            return;
        } finally {
            closeStream(bufferedInputStream);
            closeStream(bufferedOutputStream);
        }
    }

    

    /**
     * Decrypts a byte array using the supplied password  (not applicable yet)
     *
     * @param input    the byte array input
     * @param password the password
     * @return a decrypted byte array
     * @throws GeneralSecurityException if initialization, decryption, or the MAC comparison fails
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized byte[] decrypt(byte[] input, char[] password) throws GeneralSecurityException {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input is either null or empty");
        }

        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password is either null or empty");
        }

        // deconstruct the input
        byte[] initializationVector = Arrays.copyOfRange(input, 0, config.getIvLength());

        byte[] cipherText;

        // extract the MAC
        if (config.getMacAlgorithm() == CryptoInstance.MacAlgorithm.NONE) {
            cipherText = Arrays.copyOfRange(input, config.getIvLength(), input.length);
        } else {
            Mac mac = getMac(config.getMacAlgorithm(), password);

            cipherText = Arrays.copyOfRange(input, config.getIvLength(), input.length - mac.getMacLength());
            byte[] recMac = Arrays.copyOfRange(input, input.length - mac.getMacLength(), input.length);

            // compute the mac
            byte[] macBytes = mac.doFinal(cipherText);

            // verify the macs are the same
            if (!Arrays.equals(recMac, macBytes)) {
                throw new GeneralSecurityException("Received mac is different from calculated");
            }
        }

        // initialize the cipher
        cipher.init(Cipher.DECRYPT_MODE,
                deriveKey(password, initializationVector),
                getAlgorithmParameterSpec(config.getMode(), initializationVector));

        return cipher.doFinal(cipherText);
    }

    /**
     * Decrypts an input file using the supplied password
     *
     * @param input    the input file
     * @param output   the output file
     * @param password the password
     * @throws GeneralSecurityException if initialization or decryption fails
     * @throws IOException              if there's a failure to read/write from/to the input/output file
     */
    @SuppressWarnings("WeakerAccess")
    public synchronized void decrypt(File input, File output, char[] password)
            throws GeneralSecurityException, IOException {
        if (input == null || !input.exists() || input.length() <= 0) {
            throw new IllegalArgumentException("Input file is either null or does not exist");
        }

        if (output == null) {
            throw new IllegalArgumentException("Output file is null");
        }

        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password is either null or empty");
        }

        BufferedInputStream bufferedInputStream = null;
        BufferedOutputStream bufferedOutputStream = null;

        try {
            // read the mac 
            Mac mac = null;
            byte[] recMac = null;

            if (config.getMacAlgorithm() != CryptoInstance.MacAlgorithm.NONE) {
                mac = getMac(config.getMacAlgorithm(), password);

                recMac = new byte[mac.getMacLength()];

                RandomAccessFile randomAccessFile = new RandomAccessFile(input, "r");

                if (randomAccessFile.length() - mac.getMacLength() <= 0) {
                    throw new IOException("File does not contain sufficient data for decryption");
                }

                randomAccessFile.seek(randomAccessFile.length() - mac.getMacLength());
                randomAccessFile.read(recMac);

                randomAccessFile.close();
            }

            // setup streams
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(output));
            bufferedInputStream = new BufferedInputStream(new FileInputStream(input));

            // read the initialization vector
            byte[] initializationVector = new byte[config.getIvLength()];

            int ivBytesRead = bufferedInputStream.read(initializationVector);

            if (ivBytesRead < config.getIvLength()) {
                throw new IOException("File doesn't contain an IV");
            }

            // initialize the cipher
            cipher.init(Cipher.DECRYPT_MODE,
                    deriveKey(password, initializationVector),
                    getAlgorithmParameterSpec(config.getMode(), initializationVector));

            // allocate loop buffers and variables
            int bytesRead;
            int numBytesToProcess;
            byte[] inputStreamBuffer = new byte[4096];
            long bytesLeft = input.length() - config.getIvLength();

            // subtract the mac length 
            if (mac != null) {
                bytesLeft -= mac.getMacLength();
            }

            // decrypt
            while ((bytesRead = bufferedInputStream.read(inputStreamBuffer)) > 0) {
                numBytesToProcess = (bytesRead < bytesLeft) ? bytesRead : (int) bytesLeft;

                if (numBytesToProcess <= 0) {
                    break;
                }

                bufferedOutputStream.write(cipher.update(inputStreamBuffer, 0, numBytesToProcess));

                // reduce the number of bytes left
                bytesLeft -= numBytesToProcess;

                // compute the mac 
                if (mac != null) {
                    mac.update(inputStreamBuffer, 0, numBytesToProcess);
                }
            }

            // finalize the cipher
            byte[] finalDecBytes = cipher.doFinal();

            bufferedOutputStream.write(finalDecBytes);

            // compare the mac
            if (mac != null && Arrays.equals(recMac, mac.doFinal())) {
                throw new GeneralSecurityException("Received mac is different from calculated");
            }
        } finally {
            closeStream(bufferedInputStream);
            closeStream(bufferedOutputStream);
        }
    }

    /**
     * Derives an AES (javax.crypto.spec.SecretKeySpec) using a password and iteration count .
     *
     * @param password             the password
     * @param initializationVector used for PBKDF
     * @return an AES (javax.crypto.spec.SecretKeySpec)
     * @throws GeneralSecurityException if initialization, decryption, or the MAC comparison fails
     */
    private SecretKey deriveKey(char[] password, byte[] initializationVector) throws GeneralSecurityException {
        byte[] key = null;

        key = derivePbkdfKeyBytes(password, initializationVector); // use IV as salt

        return new SecretKeySpec(key, config.getAlgorithm().toString());
    }

    private byte[] derivePbkdfKeyBytes(char[] password, byte[] initializationVector)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return SecretKeyFactory.getInstance(config.getPbkdf().toString())
                .generateSecret(
                        new PBEKeySpec(
                                password,
                                initializationVector, // use IV as salt
                                config.getIterations(),
                                config.getKeyLength().bits()))
                .getEncoded();
    }

    private AlgorithmParameterSpec getAlgorithmParameterSpec(CryptoInstance.Mode mode, byte[] initializationVector) {
        switch (mode) {
            case CBC:
                return new IvParameterSpec(initializationVector);
        }

        throw new IllegalArgumentException("Unknown mode");
    }

    /**
     * Generates an initialization vector using java.security.SecureRandom as the number generator
     *
     * @return a byte array
     */
    private byte[] generateInitializationVector() {
        byte[] initializationVector = new byte[config.getIvLength()];

        new SecureRandom().nextBytes(initializationVector);

        return initializationVector;
    }

    private void closeStream(Closeable stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException ignored) {
            }
        }
    }
}
