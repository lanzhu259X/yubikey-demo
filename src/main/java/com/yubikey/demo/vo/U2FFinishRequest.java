package com.yubikey.demo.vo;

import lombok.Data;

import java.io.Serializable;

@Data
public class U2FFinishRequest implements Serializable {
    private static final long serialVersionUID = 5415538594475767306L;

    private String username;

    private String tokenResponse;
}
