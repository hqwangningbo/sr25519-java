package com.wangningbo;

import com.sun.jna.Native;

public class SR25519 implements ISR25519 {

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
    public void sr25519_ext_scrypt(byte[] var1, byte[] var2, int len1, byte[] var3, int len2, int log2_n, int r, int p) {
        lib.sr25519_ext_scrypt(var1, var2, len1, var3, len2, log2_n, r, p);
    }

    @Override
    public void sr25519_ext_sr_from_seed(byte[] var1, byte[] var2) {
        lib.sr25519_ext_sr_from_seed(var1, var2);
    }
}
