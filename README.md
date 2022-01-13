# sr25519-java

sr25519 签名Java实现，完美兼容polkadot js

### 助记词拿到种子

* byte[] toSeed(List< String > words, String passphrase)

### 获取公私钥对

* DecodeResult decodePkcs8(String encoded, String password)
* DecodeResult decodeFromSeed(String seed)
* DecodeResult decodeFromMnemonic(String mnemonic,String password)

### 签名

* byte[] sign(DecodeResult result,String message)

### 验签

* boolean verify(String sign,String message,String publicKey)

### 格式化地址

* String encodeAddress(byte[] publicKey, byte prefix)

### example

```java
class SR25519Test {
    @Test
    void decodePkcs8(){
        String encoded = "6/VMM3CoGBnloEtQolYMu5ab2T3XhqVExekzFS+2+CQAgAAAAQAAAAgAAAAUN7n........";
        String password = "xxxxxxx";
        CryptoUtils.decodePkcs8(encoded,password);
    }
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
    void signJsToVerify(){
        String encoded = "6/VMM3CoGBnloEtQolYMu5ab2T3XhqVExekzFS+2+CQAgAAAAQAAAAgAAAAUN7n1.............";
        String password = "xxxxxxx";
        DecodeResult decodeResult = CryptoUtils.decodePkcs8(encoded, password);
        byte[] sign = CryptoUtils.sign(decodeResult, "hello");
        System.out.println(HexUtils.bytesToHex(sign));
    }
    @Test
    void encodeAddress(){
        byte prefix = 42;
        String publicKey = "7263fce9f5b7bd6fca421c081860a69c8f0ef7965c1e7f9de80660d7270df55b";
        String address = CryptoUtils.encodeAddress(HexUtils.hexToBytes(publicKey), prefix);
        System.out.println(address);
    }

}
```

