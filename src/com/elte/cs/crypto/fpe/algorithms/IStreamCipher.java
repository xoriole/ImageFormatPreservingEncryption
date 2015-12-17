package com.elte.cs.crypto.fpe.algorithms;

/**
 * Interface for stream cipher used in image format preserving encryption.
 *
 * @author Sandip Pandey
 */
public interface IStreamCipher {

    public short encrypt(short input);
    public short[] encrypt(short[] input);

    public short decrypt(short input);
    public short[] decrypt(short[] input);

}
