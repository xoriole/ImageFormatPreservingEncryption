package com.elte.cs.crypto.fpe.algorithms;

/**
 * Custom RC4 implementation. 
 * This implementation of RC4 discards the key if it is 0xff.
 *
 * @author Sandip Pandey
 */
public class CustomRC4 implements IStreamCipher {

    private int[] S = new int[256];
    private final int keylen;

    /**
     * Constructor
     *
     * @param key String key for RC4
     */
    public CustomRC4(final byte[] key) {
        if (key.length < 1 || key.length > 256) {
            throw new IllegalArgumentException("key must be between 1 and 256 bytes");
        } else {
            keylen = key.length;
            for (int i = 0; i < 256; i++) {
                S[i] = i;
            }

            int j = 0;

            for (int i = 0; i < 256; i++) {
                j = (j + S[i] + key[i % keylen]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
        }
    }

    /**
     * Encrypts a single short input
     * @param input Single short input
     * @return encrypted short value
     */
    @Override
    public short encrypt(short input) {
        return transform(input);
    }

    /**
     * Encrypts a short array
     * @param input Short array of input
     * @return Encrypted short array
     */
    @Override
    public short[] encrypt(short[] input) {
        short[] output = new short[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = transform(input[i]);
        }
        return output;
    }

    /**
     * Decrypt a short input
     * @param input Short input to decrypt
     * @return decrypted short value
     */
    @Override
    public short decrypt(short input) {
        // same as encryption
        return transform(input);
    }

    /**
     * Decrypts a short array
     * @param input short array to decrypt
     * @return decrypted short array
     */
    @Override
    public short[] decrypt(short[] input) {
        // same as encryption
        return encrypt(input);
    }

    /**
     * Transform the input. XOR key byte with input
     *
     * @param input Input byte
     * @return input xored with key byte
     */
    public short transform(final short input) {
        short output = 0;

        int i = 0, j = 0, k, t;

        boolean success = false;
        while (!success) {
            i = (i + 1);
            j = (j + S[i]);
            S[i] ^= S[j];
            S[j] ^= S[i];
            S[i] ^= S[j];
            t = (S[i] + S[j]) % 256;
            k = S[t];
            if (k != 0xff) {
                success = true;
                output = (short) ((input ^ k));
            }
        }

        return output;
    }

    /**
     * Next Key byte
     *
     * @return next key byte
     */
    public short nextKeyByte() {
        int i = 0, j = 0, k, t;

        boolean success = false;
        while (!success) {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            S[i] ^= S[j];
            S[j] ^= S[i];
            S[i] ^= S[j];
            t = (S[i] + S[j]) % 256;
            k = S[t];
            if (k != 0xff) {
                success = true;
                return (short) k;
            }
        }
        return 0;
    }

}
