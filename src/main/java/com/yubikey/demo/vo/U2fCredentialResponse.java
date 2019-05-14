package com.yubikey.demo.vo;

import com.yubico.webauthn.data.ByteArray;
import lombok.Data;

import java.io.Serializable;

@Data
public class U2fCredentialResponse implements Serializable {

    private static final long serialVersionUID = -8834859746169247935L;

    private final ByteArray keyHandle;

    private final ByteArray publicKey;

    private final ByteArray attestationCertAndSignature;

    private final ByteArray clientDataJSON;

}
