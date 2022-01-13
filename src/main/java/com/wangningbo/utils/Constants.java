package com.wangningbo.utils;

import com.google.common.collect.Lists;
import com.google.common.primitives.UnsignedBytes;

import java.util.List;

public class Constants {
    public static final byte[] PKCS8_DIVIDER = new byte[]{UnsignedBytes.checkedCast(161), 35, 3, 33, 0};
    public static final byte[] PKCS8_HEADER = new byte[]{48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32};
    public static final int SR25519_CHAINCODE_SIZE = 32;
    public static final int SR25519_KEYPAIR_SIZE = 96;
    public static final int SR25519_PUBLIC_SIZE = 32;
    public static final int SR25519_SECRET_SIZE = 64;
    public static final int SR25519_SEED_SIZE = 32;
    public static final int SR25519_SIGNATURE_SIZE = 64;
    public static final int NONCE_LENGTH = 24;
    public static final int SCRYPT_LENGTH = 32 + (3 * 4);

    public static List<Integer> allowedDecodedLengths = Lists.newArrayList(1, 2, 4, 8, 32);
    public static List<Integer> allowedEncodedLengths = Lists.newArrayList(3, 4, 6, 10, 35);
    public static List<Integer> allowedPrefix = Lists.newArrayList(0, 1, 3, 42, 43, 68, 69);
    public static byte prefix = 42;
}
