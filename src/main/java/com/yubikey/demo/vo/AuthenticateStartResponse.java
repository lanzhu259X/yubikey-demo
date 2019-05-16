package com.yubikey.demo.vo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Builder
@Data
public class AuthenticateStartResponse implements Serializable {

    private static final long serialVersionUID = -2582985085987828933L;

    private ByteArray requestId;

    private String username;

    private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @JsonIgnore
    private AssertionRequest request;

}
