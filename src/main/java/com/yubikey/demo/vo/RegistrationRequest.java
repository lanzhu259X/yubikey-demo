package com.yubikey.demo.vo;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import lombok.Data;

import java.io.Serializable;

@Data
public class RegistrationRequest implements Serializable {

    private static final long serialVersionUID = 4795768082489208979L;

    private String username;

    private String displayName;

    private String credentialNickname;

    private boolean requireResidentKey;

    private ByteArray requestId;

    private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
}
