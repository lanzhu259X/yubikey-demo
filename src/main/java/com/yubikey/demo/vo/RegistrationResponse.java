package com.yubikey.demo.vo;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Builder
@Data
public class RegistrationResponse implements Serializable {
    private static final long serialVersionUID = -3291894190175041830L;

    private ByteArray requestId;

    private String appId;

    private String username;

    private String credentialNickname;

    private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
}
