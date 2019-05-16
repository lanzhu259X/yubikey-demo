package com.yubikey.demo.vo;

import lombok.Data;

import java.io.Serializable;

@Data
public class DeregisterCredentialRequest implements Serializable {

    private static final long serialVersionUID = 2968342926478357566L;

    private String username;

    private String credentialIdBase64;
}
