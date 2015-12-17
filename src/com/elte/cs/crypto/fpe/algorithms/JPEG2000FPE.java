package com.elte.cs.crypto.fpe.algorithms;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Format preserving encryption for JPEG 2000 files.
 *
 * @author Sandip Pandey
 */
public class JPEG2000FPE {

    /**
     * Symmetric Key for stream cipher
     */
    protected String key;

    /**
     * Symmetric algorithm to use
     */
    protected String algorithm;

    /**
     * Stream cipher
     */
    protected IStreamCipher cipher;

    /**
     * Setup the key with default stream cipher (RC4)
     * @param key Key for stream cipher
     */
    public void setup(String key) {
        this.key = key;
        this.algorithm = "RC4";
    }

    /**
     * Setup the key and algorithm to use
     * @param key Key for encryption/decryption
     * @param algorithm Stream cipher algorithm
     */
    public void setup(String key, String algorithm) {
        this.key = key;
        this.algorithm = algorithm;
    }

    /**
     * Encrypts an image file (JPEG2000 only)
     * @param inputFile Input file
     * @param outputFile Output file with encrypted image
     */
    public void encrypt(String inputFile, String outputFile) {

        // initialize the cipher
        initializeCipher();

        try {
            // byte buffer of the input file
            Path path = Paths.get(inputFile);
            byte[] plainDataBuffer = Files.readAllBytes(path);

            // byte buffer for encrypted bytes
            byte[] encryptedDataBuffer = new byte[plainDataBuffer.length];

            // byte index
            int i = 0;

            //copy till first occurance of SOD
            while (!isNextSOT(plainDataBuffer, i)) {
                encryptedDataBuffer[i] = plainDataBuffer[i];
                i++;
            }

            // flag for end of codestream indicator
            boolean end = false;

            while (!end) {

                // if next tile is present; copy header
                if (isNextSOT(plainDataBuffer, i)) {
                    // copy SOT bytes
                    encryptedDataBuffer[i] = plainDataBuffer[i];
                    i++;
                    encryptedDataBuffer[i] = plainDataBuffer[i];
                    i++;

                    while (!(isNextSOD(plainDataBuffer, i))) {
                        encryptedDataBuffer[i] = plainDataBuffer[i];
                        i++;
                    }

                    // copy SOD bytes
                    encryptedDataBuffer[i] = plainDataBuffer[i];
                    i++;
                    encryptedDataBuffer[i] = plainDataBuffer[i];
                    i++;

                    // for first byte after SOD
                    short firstByte = (short) (plainDataBuffer[i]);
                    if ((firstByte & 0xff) == 0xff) {
                        encryptedDataBuffer[i] = (byte) firstByte;
                    } else {
                        encryptedDataBuffer[i] = (byte) (cipher.encrypt(firstByte) % 0xff);
                    }

                    // increment index
                    i++;

                    // iterate till next tile or end of codestream is found
                    while (!(isNextSOT(plainDataBuffer, i) || isNextEOC(plainDataBuffer, i))) {

                        short _currentByte = (short) (plainDataBuffer[i]);
                        short _prevByte = (short) (plainDataBuffer[i - 1]);

                        // Don't encrypt if current or previous byte is FF
                        if ((_currentByte & 0xff) == 0xff || (_prevByte & 0xff) == 0xff) {
                            encryptedDataBuffer[i] = plainDataBuffer[i];
                        } else {
                            encryptedDataBuffer[i] = (byte) cipher.encrypt(_currentByte);
                        }

                        // increment index
                        i++;

                    }

                }

                // if end of codestream
                if (isNextEOC(plainDataBuffer, i)) {
                    // copy EOD bytes
                    encryptedDataBuffer[i] = plainDataBuffer[i];
                    i++;
                    encryptedDataBuffer[i] = plainDataBuffer[i];
                    i++;

                    end = true;
                }

            }

            // Write the encrypted data buffer to file
            writeBinaryFile(outputFile, encryptedDataBuffer);

        } catch (IOException ex) {
            Logger.getLogger(JPEG2000FPE.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Decrypts an input file with encrypted image
     * @param inputFile Input file with encrypted image
     * @param outputFile Output file
     */
    public void decrypt(String inputFile, String outputFile) {

        // initialize the cipher
        initializeCipher();

        try {
            // byte buffer of the input file
            Path path = Paths.get(inputFile);
            byte[] encryptedDataBuffer = Files.readAllBytes(path);

            // byte buffer for encrypted bytes
            byte[] decryptedDataBuffer = new byte[encryptedDataBuffer.length];

            // byte index
            int i = 0;

            //copy till first occurance of SOD
            while (!isNextSOT(encryptedDataBuffer, i)) {
                decryptedDataBuffer[i] = encryptedDataBuffer[i];
                i++;
            }

            // flag for end of codestream indicator
            boolean end = false;

            while (!end) {

                // if next tile is present; copy header
                if (isNextSOT(encryptedDataBuffer, i)) {
                    // copy SOT bytes
                    decryptedDataBuffer[i] = encryptedDataBuffer[i];
                    i++;
                    decryptedDataBuffer[i] = encryptedDataBuffer[i];
                    i++;

                    while (!(isNextSOD(encryptedDataBuffer, i))) {
                        decryptedDataBuffer[i] = encryptedDataBuffer[i];
                        i++;
                    }

                    // copy SOD bytes
                    decryptedDataBuffer[i] = encryptedDataBuffer[i];
                    i++;
                    decryptedDataBuffer[i] = encryptedDataBuffer[i];
                    i++;

                    // for first byte after SOD
                    short firstByte = (short) (encryptedDataBuffer[i]);
                    if ((firstByte & 0xff) == 0xff) {
                        decryptedDataBuffer[i] = (byte) firstByte;
                    } else {
                        decryptedDataBuffer[i] = (byte) (cipher.decrypt(firstByte) % 0xff);
                    }

                    // increment index
                    i++;

                    // iterate till next tile or end of codestream is found
                    while (!(isNextSOT(encryptedDataBuffer, i) || isNextEOC(encryptedDataBuffer, i))) {

                        short _currentByte = (short) (encryptedDataBuffer[i]);
                        short _prevByte = (short) (encryptedDataBuffer[i - 1]);

                        // Don't encrypt if current or previous byte is FF
                        if ((_currentByte & 0xff) == 0xff || (_prevByte & 0xff) == 0xff) {
                            decryptedDataBuffer[i] = encryptedDataBuffer[i];
                        } else {
                            decryptedDataBuffer[i] = (byte) cipher.decrypt(_currentByte);
                        }

                        // increment index
                        i++;

                    }

                }

                // if end of codestream
                if (isNextEOC(encryptedDataBuffer, i)) {
                    // copy EOD bytes
                    decryptedDataBuffer[i] = encryptedDataBuffer[i];
                    i++;
                    decryptedDataBuffer[i] = encryptedDataBuffer[i];
                    i++;

                    end = true;
                }

            }

            // Write the decrypted data buffer to file
            writeBinaryFile(outputFile, decryptedDataBuffer);

        } catch (IOException ex) {
            Logger.getLogger(JPEG2000FPE.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    // Getters and setters

    /**
     * Gets the key
     * @return Key used for encryption/decryption
     */
    public String getKey() {
        return key;
    }

    /**
     * Sets the key
     * @param key Key to use for encryption/decryption
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     * Gets the symmetric key algorithm used
     * @return algorithm used for encryption/decryption
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Sets the algorithm to use for encryption/decryption
     * @param algorithm Algorithm e.g RC4
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    // Private Helper methods
    /**
     * Checks if the next byte is start of Data marker (0xFF93)
     * @param input byte array
     * @param index index in byte array
     * @return boolean
     */
    private boolean isNextSOD(byte[] input, int index) {
        short currentByte = (short) (input[index] & 0xff);
        short nextByte = (short) (input[index + 1] & 0xff);
        return (currentByte == 0xff && nextByte == 0x93);
    }

    /**
     * Checks if the next byte is start of tile marker (0xFF90)
     * @param input byte array
     * @param index index in byte array
     * @return boolean
     */
    private boolean isNextSOT(byte[] input, int index) {
        short currentByte = (short) (input[index] & 0xff);
        short nextByte = (short) (input[index + 1] & 0xff);
        return (currentByte == 0xff && nextByte == 0x90);
    }

    /**
     * Checks if the next byte is end of code-stream marker (0xFFD9)
     * @param input byte array
     * @param index index in byte array
     * @return boolean
     */
    private boolean isNextEOC(byte[] input, int index) {
        short currentByte = (short) (input[index] & 0xff);
        short nextByte = (short) (input[index + 1] & 0xff);
        return (currentByte == 0xff && nextByte == 0xd9);
    }

    private void initializeCipher() {

        if (this.algorithm.equals("RC4")) {
            this.cipher = new CustomRC4(key.getBytes());
        }

    }

    private static void writeBinaryFile(String path, byte[] bytes) throws FileNotFoundException, IOException {
        FileOutputStream stream = new FileOutputStream(path);
        try {
            stream.write(bytes);
        } finally {
            stream.close();
        }
    }

    public static void main(String[] args) {
        String inputfile = "img/1.jp2";
        String encryptedFile = "img/enc2.jp2";
        String decryptedFile = "img/dec2.jp2";

        // setup parameters
        String key = "password123";
        String algo = "RC4";

        JPEG2000FPE fpe = new JPEG2000FPE();
        fpe.setup(key, algo);

        // encrypt image
        fpe.encrypt(inputfile, encryptedFile);

        // decrypt image
        fpe.decrypt(encryptedFile, decryptedFile);
    }

}
