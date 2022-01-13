package com.wangningbo.pojo;

import lombok.Data;

@Data
public class DecodeResult {
    private byte[] publicKey;
    private byte[] privateKey;
}
