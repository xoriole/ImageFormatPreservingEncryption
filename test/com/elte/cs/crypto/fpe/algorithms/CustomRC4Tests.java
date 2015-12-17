package com.elte.cs.crypto.fpe.algorithms;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Sandip Pandey
 */
public class CustomRC4Tests {

    private String key;
    private CustomRC4 rc4Encrypter;
    private CustomRC4 rc4Decrypter;

    @Before
    public void setUp() {
        key = "strongkey";
        rc4Encrypter = new CustomRC4(key.getBytes());
        rc4Decrypter = new CustomRC4(key.getBytes());
    }

    @Test
    public void testEncryption() {
        short input1 = -22;
        short input2 = 0xff;

        short enc1 = rc4Encrypter.transform(input1);
        short enc2 = rc4Encrypter.transform(input2);
        
        short dec1 = rc4Decrypter.transform(enc1);
        short dec2 = rc4Decrypter.transform(enc2);

        Assert.assertEquals(input1, dec1);
        Assert.assertEquals(input2, dec2);
    }
}
