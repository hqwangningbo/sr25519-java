package com.wangningbo;

import com.wangningbo.pojo.DecodeResult;
import com.wangningbo.utils.CryptoUtils;
import com.wangningbo.utils.HexUtils;
import org.junit.jupiter.api.Test;

class SR25519Test {

    @Test
    void decodeFromSeed(){
        String seed = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
        CryptoUtils.decodeFromSeed(seed);
    }
    @Test
    void decodeFromMnemonic(){
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        String password = "";
        DecodeResult decodeResult = CryptoUtils.decodeFromMnemonic(mnemonic, password);
        System.out.println(HexUtils.bytesToHex(decodeResult.getPrivateKey()));
        System.out.println(HexUtils.bytesToHex(decodeResult.getPublicKey()));
    }
    @Test
    void sign(){
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        String password = "";
        DecodeResult decodeResult = CryptoUtils.decodeFromMnemonic(mnemonic, password);
        byte[] sign = CryptoUtils.sign(decodeResult, "hello");
        System.out.println("signature:"+HexUtils.bytesToHex(sign));
    }
    @Test
    void verify(){
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        String password = "";
        DecodeResult decodeResult = CryptoUtils.decodeFromMnemonic(mnemonic, password);
        byte[] sign = CryptoUtils.sign(decodeResult, "hello");
        System.out.println("signature:"+HexUtils.bytesToHex(sign));
        boolean result = CryptoUtils.verify(HexUtils.bytesToHex(sign), "hello", HexUtils.bytesToHex(decodeResult.getPublicKey()));
        System.out.println(result);
    }
    @Test
    void encodeAddress(){
        byte prefix = 42;
        String publicKey = "7263fce9f5b7bd6fca421c081860a69c8f0ef7965c1e7f9de80660d7270df55b";
        String address = CryptoUtils.encodeAddress(HexUtils.hexToBytes(publicKey), prefix);
        System.out.println(address);
    }

}