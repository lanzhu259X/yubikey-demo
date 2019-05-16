package com.yubikey.demo.vo;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import lombok.Data;

import java.io.Serializable;

@Data
public class AssertionFinishRequest implements Serializable {
    private static final long serialVersionUID = -4828691533492527992L;

    private ByteArray requestId;

    /**
     * 是否访问的是注销操作
     */
    private boolean deregister;

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;

    public AssertionFinishRequest(
            @JsonProperty("requestId") ByteArray requestId,
            @JsonProperty("credential") PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential
            ) {
        this.requestId = requestId;
        this.credential = credential;
    }
}
