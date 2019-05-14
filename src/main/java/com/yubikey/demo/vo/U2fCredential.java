package com.yubikey.demo.vo;

import lombok.Data;

import java.io.Serializable;

@Data
public class U2fCredential implements Serializable {

    private static final long serialVersionUID = -6040486118746459008L;

    private U2fCredentialResponse u2fResponse;
}
