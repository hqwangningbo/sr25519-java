package com.wangningbo.utils;

import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;
import com.wangningbo.SR25519;
import com.wangningbo.pojo.DecodeResult;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.PBKDF2SHA512;

import java.util.Arrays;
import java.util.List;


public class CryptoUtils {
    public static byte[] toSeed(List<String> words, String passphrase) {
        String pass = Utils.SPACE_JOINER.join(words);
        String salt = "mnemonic" + passphrase;
        final Stopwatch watch = Stopwatch.createStarted();
        byte[] seed = PBKDF2SHA512.derive(pass, salt, 2048, Constants.SR25519_SEED_SIZE);
        watch.stop();
        return seed;
    }
    public static DecodeResult decodePkcs8(String encoded, String password) {
        SR25519 sr25519 = new SR25519();
        byte[] encrypted = Base64.decodeBase64(encoded);
        byte[] salt = new byte[32];
        System.arraycopy(encrypted,0,salt,0,32);
        byte[] scrypt_password = new byte[64];
        sr25519.sr25519_ext_scrypt(
                scrypt_password,
                password.getBytes(),
                password.getBytes().length,
                salt,
                salt.length,
                15,
                8,
                1
        );
        byte[] readyEncrypted = new byte[encrypted.length-Constants.SCRYPT_LENGTH];
        System.arraycopy(encrypted,Constants.SCRYPT_LENGTH,readyEncrypted,0,encrypted.length-Constants.SCRYPT_LENGTH);
        byte[] encrypted3 = new byte[encrypted.length-Constants.SCRYPT_LENGTH-Constants.NONCE_LENGTH];
        System.arraycopy(readyEncrypted,Constants.NONCE_LENGTH,encrypted3,0,encrypted.length-Constants.SCRYPT_LENGTH-Constants.NONCE_LENGTH);
        byte[] nonce = new byte[24];
        System.arraycopy(readyEncrypted,0,nonce,0,Constants.NONCE_LENGTH);
        byte[] key = new byte[32];
        System.arraycopy(scrypt_password,0,key,0,32);
        byte[] decrypted = TweetNaCl.secretbox_open(encrypted3, nonce, key);
        byte[] publicKey = new byte[Constants.SR25519_PUBLIC_SIZE];
        int SEED_OFFSET = Constants.PKCS8_HEADER.length;
        int divOffset = SEED_OFFSET + Constants.SR25519_SECRET_SIZE;
        int pubOffset = divOffset+Constants.PKCS8_DIVIDER.length;
        System.arraycopy(decrypted,pubOffset,publicKey,0,Constants.SR25519_PUBLIC_SIZE);
        byte[] privateKey = new byte[Constants.SR25519_SECRET_SIZE];
        System.arraycopy(decrypted,SEED_OFFSET,privateKey,0,Constants.SR25519_SECRET_SIZE);
        DecodeResult decodeResult = new DecodeResult();
        decodeResult.setPrivateKey(privateKey);
        decodeResult.setPublicKey(publicKey);
        return decodeResult;
    }
    public static DecodeResult decodeFromSeed(String seed){
        SR25519 sr25519 = new SR25519();
        byte[] keypair = new byte[Constants.SR25519_KEYPAIR_SIZE];
        sr25519.sr25519_ext_sr_from_seed(keypair, HexUtils.hexToBytes(seed));
        byte[] privateKey = new byte[Constants.SR25519_SECRET_SIZE];
        byte[] publicKey = new byte[Constants.SR25519_PUBLIC_SIZE];
        System.arraycopy(keypair,0,privateKey,0,Constants.SR25519_SECRET_SIZE);
        System.arraycopy(keypair,Constants.SR25519_SECRET_SIZE,publicKey,0,Constants.SR25519_PUBLIC_SIZE);
        DecodeResult decodeResult = new DecodeResult();
        decodeResult.setPrivateKey(privateKey);
        decodeResult.setPublicKey(publicKey);
        return decodeResult;
    }
    public static DecodeResult decodeFromMnemonic(String mnemonic,String password){
        String[] s = mnemonic.split(" ");
        List<String> words = Arrays.asList(s);
        byte[] seed = toSeed(words, password);
        SR25519 sr25519 = new SR25519();
        byte[] keypair = new byte[Constants.SR25519_KEYPAIR_SIZE];
        sr25519.sr25519_ext_sr_from_seed(keypair, seed);
        byte[] privateKey = new byte[Constants.SR25519_SECRET_SIZE];
        byte[] publicKey = new byte[Constants.SR25519_PUBLIC_SIZE];
        System.arraycopy(keypair,0,privateKey,0,Constants.SR25519_SECRET_SIZE);
        System.arraycopy(keypair,Constants.SR25519_SECRET_SIZE,publicKey,0,Constants.SR25519_PUBLIC_SIZE);
        DecodeResult decodeResult = new DecodeResult();
        decodeResult.setPrivateKey(privateKey);
        decodeResult.setPublicKey(publicKey);
        return decodeResult;
    }
    public static byte[] sign(DecodeResult result,String message){
    SR25519 sr25519 = new SR25519();
    byte[] sign = new byte[Constants.SR25519_SIGNATURE_SIZE];
    sr25519.sr25519_ext_sr_sign(
            sign,
            result.getPublicKey(),
            result.getPrivateKey(),
            message.getBytes(),
            message.getBytes().length
    );
    return sign;
}
    public static boolean verify(String sign,String message,String publicKey){
    SR25519 sr25519 = new SR25519();
    return sr25519.sr25519_ext_sr_verify(
            HexUtils.hexToBytes(sign),
            message.getBytes(),
            message.getBytes().length,
            HexUtils.hexToBytes(publicKey)
    );
}
    public static String encodeAddress(byte[] publicKey, byte prefix) {
        byte[] key = com.wangningbo.utils.Utils.u8aToU8a(publicKey);
        assert Constants.allowedDecodedLengths.contains(key.length)
                : "Expected a valid key to convert, with length " + Constants.allowedDecodedLengths + " : " + key.length;
        boolean isPublicKey = key.length == 32;

        byte[] input = com.wangningbo.utils.Utils.u8aConcat(Lists.newArrayList(new byte[]{prefix}, key));
        byte[] hash = com.wangningbo.utils.Utils.sshash(input);
        byte[] bytes = com.wangningbo.utils.Utils.u8aConcat(Lists.newArrayList(input, ArrayUtils.subarray(hash, 0, isPublicKey ? 2 : 1)));
        String result = Base58.encode(bytes);
        return result;
    }
}
