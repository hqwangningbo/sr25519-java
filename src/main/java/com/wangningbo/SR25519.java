package com.wangningbo;

import com.sun.jna.Native;

public class SR25519 implements ISR25519 {
    public static final int SR25519_CHAINCODE_SIZE = 32;

    public static final int SR25519_KEYPAIR_SIZE = 96;

    public static final int SR25519_PUBLIC_SIZE = 32;

    public static final int SR25519_SECRET_SIZE = 64;

    public static final int SR25519_SEED_SIZE = 32;

    public static final int SR25519_SIGNATURE_SIZE = 64;

    public static ISR25519 lib = (ISR25519) Native.load("rust", ISR25519.class);

    @Override
    public void sr25519_derive_keypair_hard(byte[] var1, byte[] var2, byte[] var3) {
        lib.sr25519_derive_keypair_hard(var1,var2,var3);
    }

    @Override
    public void sr25519_derive_keypair_soft(byte[] var1, byte[] var2, byte[] var3) {
        lib.sr25519_derive_keypair_soft(var1,var2,var3);
    }

    @Override
    public void sr25519_derive_public_soft(byte[] var1, byte[] var2, byte[] var3) {
        lib.sr25519_derive_public_soft(var1,var2,var3);
    }


    @Override
    public void sr25519_ext_sr_sign(byte[] var1, byte[] var2, byte[] var3, byte[] var4, int len) {
        lib.sr25519_ext_sr_sign(var1, var2, var3, var4, len);
    }


    @Override
    public boolean sr25519_ext_sr_verify(byte[] var1, byte[] var2, int len, byte[] var3) {
       return lib.sr25519_ext_sr_verify(var1, var2, len, var3);
    }

    @Override
    public void sr25519_ext_sr_from_seed(byte[] var1, byte[] var2) {
        lib.sr25519_ext_sr_from_seed(var1, var2);
    }
}
