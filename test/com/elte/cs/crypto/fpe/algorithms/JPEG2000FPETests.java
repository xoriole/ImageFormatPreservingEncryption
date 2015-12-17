package com.elte.cs.crypto.fpe.algorithms;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Sandip Pandey
 */
public class JPEG2000FPETests {

    private String inputFile;
    private String encryptedFile;
    private String decryptedFile;

    private String key;
    private String algorithm;

    private JPEG2000FPE fpe;

    @Before
    public void setUp() {

        inputFile = "img/1.jp2";
        encryptedFile = "img/enc1.jp2";
        decryptedFile = "img/dec1.jp2";

        key = "password123";
        algorithm = "RC4";

        fpe = new JPEG2000FPE();
        fpe.setup(key, algorithm);

    }

    @Test
    public void testForSameSize() {
        // encrypt
        fpe.encrypt(inputFile, encryptedFile);

        // decrypt
        fpe.decrypt(encryptedFile, decryptedFile);

        try {
            // check for file size of inputfile, encrypted file, decrypted file
            long inputFileSize = Files.size(Paths.get(inputFile));
            long encryptedFileSize = Files.size(Paths.get(encryptedFile));
            long decryptedFileSize = Files.size(Paths.get(decryptedFile));

            assertEquals(inputFileSize, encryptedFileSize);
            assertEquals(encryptedFileSize, decryptedFileSize);
        } catch (IOException ex) {
            fail("IO Exception. Check if file exists.");
        }

    }

    @Test
    public void testForHash() {
        // encrypt
        fpe.encrypt(inputFile, encryptedFile);

        // decrypt
        fpe.decrypt(encryptedFile, decryptedFile);

        // check for file size of inputfile, encrypted file, decrypted file
        String inputFileHash = getHash(inputFile);
        String decryptedFileHash = getHash(decryptedFile);

        assertEquals(inputFileHash, decryptedFileHash);

    }

    private String getHash(String filename) {

        String hash = "";

        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            FileInputStream fis = new FileInputStream(filename);
            byte[] dataBytes = new byte[1024];

            int nread = 0;

            while ((nread = fis.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, nread);
            };

            byte[] mdbytes = md.digest();

            //convert the byte to hex format
            StringBuffer sb = new StringBuffer("");
            for (int i = 0; i < mdbytes.length; i++) {
                sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            hash = sb.toString();

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(JPEG2000FPETests.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(JPEG2000FPETests.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(JPEG2000FPETests.class.getName()).log(Level.SEVERE, null, ex);
        }

        return hash;
    }

}
