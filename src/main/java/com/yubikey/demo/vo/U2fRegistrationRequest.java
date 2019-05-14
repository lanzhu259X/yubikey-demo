package com.yubikey.demo.vo;

import lombok.Data;

import java.io.Serializable;

@Data
public class U2fRegistrationRequest implements Serializable {

    private String requestId;

    private U2fCredential credential;

}
