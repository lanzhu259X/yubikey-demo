package com.yubikey.demo.util;

import com.yubico.webauthn.data.ByteArray;

import java.security.SecureRandom;

public class YubicoHelper {

    private static final SecureRandom random = new SecureRandom();

    public static ByteArray geneateRandom(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }
}
