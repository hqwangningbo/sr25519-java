package com.wangningbo;

import com.wangningbo.utils.HexUtils;
import org.junit.Before;
import org.junit.jupiter.api.Test;

import javax.swing.text.Utilities;
import java.util.Arrays;
import java.util.List;

class SR25519Test {
    @Test
    void get_seed_from_code() {
        String expected_seed="44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e33f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453";
        String[] s = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" ");
        List<String> words = Arrays.asList(s);
        byte[] seedTest = HexUtils.toSeed(words, "ss");
        System.out.println("seedTest:" + HexUtils.bytesToHex(seedTest));
    }
    @Test
    void sr25519_ext_sr_from_seed(){
        String expected_seed="44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e33f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453";
        SR25519 sr25519 = new SR25519();
        String seed = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
        byte[] keypair = new byte[SR25519.SR25519_KEYPAIR_SIZE];
        sr25519.sr25519_ext_sr_from_seed(keypair, HexUtils.hexToBytes(seed));
        System.out.println(keypair.length);
        System.out.println("keypair:"+ HexUtils.bytesToHex(keypair));
        byte[] privateKey = new byte[SR25519.SR25519_SECRET_SIZE];
        byte[] publicKey = new byte[SR25519.SR25519_PUBLIC_SIZE];
        System.arraycopy(keypair,0,privateKey,0,SR25519.SR25519_SECRET_SIZE);
        System.arraycopy(keypair,SR25519.SR25519_SECRET_SIZE,publicKey,0,SR25519.SR25519_PUBLIC_SIZE);
        System.out.println("privateKey:"+HexUtils.bytesToHex(privateKey));
        System.out.println("publicKey:"+HexUtils.bytesToHex(publicKey));
    }
    @Test
    void sr25519_ext_sr_sign(){
        SR25519 sr25519 = new SR25519();
        String seed = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
        byte[] keypair = new byte[SR25519.SR25519_KEYPAIR_SIZE];
        sr25519.sr25519_ext_sr_from_seed(keypair, HexUtils.hexToBytes(seed));
        System.out.println("keypair:"+ HexUtils.bytesToHex(keypair));
        byte[] privateKey = new byte[SR25519.SR25519_SECRET_SIZE];
        byte[] publicKey = new byte[SR25519.SR25519_PUBLIC_SIZE];
        System.arraycopy(keypair,0,privateKey,0,SR25519.SR25519_SECRET_SIZE);
        System.arraycopy(keypair,SR25519.SR25519_SECRET_SIZE,publicKey,0,SR25519.SR25519_PUBLIC_SIZE);
        System.out.println("privateKey:"+HexUtils.bytesToHex(privateKey));
        System.out.println("publicKey:"+HexUtils.bytesToHex(publicKey));
        String message = "hello";
        byte[] sign = new byte[SR25519.SR25519_SIGNATURE_SIZE];
        sr25519.sr25519_ext_sr_sign(
                sign,
                publicKey,
                privateKey,
                message.getBytes(),
                message.getBytes().length
        );
        System.out.println("signature:"+HexUtils.bytesToHex(sign));

    }
    @Test
    void sr25519_verify(){
        String expected_seed="44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e33f50c3d5c84fa3e5399c72d6cbbbbc4a49bf76f76d952f479d74655a2ef2d453";
        SR25519 sr25519 = new SR25519();
        String seed = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
        byte[] keypair = new byte[SR25519.SR25519_KEYPAIR_SIZE];
        sr25519.sr25519_ext_sr_from_seed(keypair, HexUtils.hexToBytes(seed));
        System.out.println("keypair:"+ HexUtils.bytesToHex(keypair));
        byte[] privateKey = new byte[SR25519.SR25519_SECRET_SIZE];
        byte[] publicKey = new byte[SR25519.SR25519_PUBLIC_SIZE];
        System.arraycopy(keypair,0,privateKey,0,SR25519.SR25519_SECRET_SIZE);
        System.arraycopy(keypair,SR25519.SR25519_SECRET_SIZE,publicKey,0,SR25519.SR25519_PUBLIC_SIZE);
        System.out.println("privateKey:"+HexUtils.bytesToHex(privateKey));
        System.out.println("publicKey:"+HexUtils.bytesToHex(publicKey));

        String message = "hello";
        byte[] sign = new byte[SR25519.SR25519_SIGNATURE_SIZE];
        sr25519.sr25519_ext_sr_sign(
                sign,
                publicKey,
                privateKey,
                message.getBytes(),
                message.getBytes().length
        );
        System.out.println("signature:"+HexUtils.bytesToHex(sign));

        boolean result = sr25519.sr25519_ext_sr_verify(
                sign,
                message.getBytes(),
                message.getBytes().length,
                publicKey
        );

        System.out.println(result);
    }

    @Test
    void call_verify_known_message(){
        SR25519 sr25519 = new SR25519();
        String message = "I hereby verify that I control 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        String sign = "1037eb7e51613d0dcf5930ae518819c87d655056605764840d9280984e1b7063c4566b55bf292fcab07b369d01095879b50517beca4d26e6a65866e25fec0d83";
        String publicKey = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
        boolean result = sr25519.sr25519_ext_sr_verify(
                HexUtils.hexToBytes(sign),
                message.getBytes(),
                message.getBytes().length,
                HexUtils.hexToBytes(publicKey)
        );
        System.out.println(result);

    }

}