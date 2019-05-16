package com.yubikey.demo.vo;

import lombok.Data;

import java.io.Serializable;

@Data
public class AuthenticateStartRequest implements Serializable {
    private static final long serialVersionUID = -4596762401532479607L;

    private String username;
}
