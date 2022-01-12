package com.wangningbo.utils;


import com.google.common.base.Stopwatch;
import org.bitcoinj.crypto.PBKDF2SHA512;

import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;

public class HexUtils {

    /**
     * Constant-time byte comparison.
     *
     * @param b a byte
     * @param c a byte
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(int b, int c) {
        int result = 0;
        int xor = b ^ c;
        for (int i = 0; i < 8; i++) {
            result |= xor >> i;
        }
        return (result ^ 0x01) & 0x01;
    }

    /**
     * Constant-time byte[] comparison.
     *
     * @param b a byte[]
     * @param c a byte[]
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(byte[] b, byte[] c) {
        int result = 0;
        for (int i = 0; i < 32; i++) {
            result |= b[i] ^ c[i];
        }

        return equal(result, 0);
    }

    /**
     * Constant-time determine if byte is negative.
     *
     * @param b the byte to check.
     * @return 1 if the byte is negative, 0 otherwise.
     */
    public static int negative(int b) {
        return (b >> 8) & 1;
    }

    /**
     * Get the i'th bit of a byte array.
     *
     * @param h the byte array.
     * @param i the bit index.
     * @return 0 or 1, the value of the i'th bit in h
     */
    public static int bit(byte[] h, int i) {
        return (h[i >> 3] >> (i & 7)) & 1;
    }

    /**
     * Converts a hex string to bytes.
     *
     * @param s the hex string to be converted.
     * @return the byte[]
     */
    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Converts bytes to a hex string.
     *
     * @param raw the byte[] to be converted.
     * @return the hex representation as a string.
     */
    public static String bytesToHex(byte[] raw) {
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(Character.forDigit((b & 0xF0) >> 4, 16))
                    .append(Character.forDigit((b & 0x0F), 16));
        }
        return hex.toString();
    }
    public static byte[] subByte(byte[] b, int off, int length) {
        byte[] b1 = new byte[length];
        System.arraycopy(b, off, b1, 0, length);
        return b1;
    }

    public static byte[] toSeed(List<String> words, String passphrase) {
        checkNotNull(passphrase, "A null passphrase is not allowed.");

        // To create binary seed from mnemonic, we use PBKDF2 function
        // with mnemonic sentence (in UTF-8) used as a password and
        // string "mnemonic" + passphrase (again in UTF-8) used as a
        // salt. Iteration count is set to 4096 and HMAC-SHA512 is
        // used as a pseudo-random function. Desired length of the
        // derived key is 512 bits (= 64 bytes).
        //
        String pass = org.bitcoinj.core.Utils.SPACE_JOINER.join(words);
        String salt = "mnemonic" + passphrase;

        final Stopwatch watch = Stopwatch.createStarted();
        byte[] seed = PBKDF2SHA512.derive(pass, salt, 2048, 32);
        watch.stop();
        return seed;
    }
}
