package com.wangningbo;

import com.sun.jna.Library;

public interface ISR25519 extends Library{
    void sr25519_derive_keypair_hard(byte[] var1, byte[] var2, byte[] var3);
    void sr25519_derive_keypair_soft(byte[] var1, byte[] var2, byte[] var3);
    void sr25519_derive_public_soft(byte[] var1, byte[] var2, byte[] var3);
    void sr25519_ext_sr_sign(byte[] var1, byte[] var2,byte[] var3,byte[] var4,int len);
    void sr25519_ext_sr_from_seed(byte[] var1, byte[] var2);
    boolean sr25519_ext_sr_verify(byte[] var1, byte[] var2,int len,byte[] var3);
    void sr25519_ext_scrypt(byte[] var1, byte[] var2,int len1,byte[] var3,int len2,int log2_n,int r,int p);

}
