package com.yubikey.demo.vo;

import lombok.Data;

import java.io.Serializable;

@Data
public class U2FRequest implements Serializable {

    private static final long serialVersionUID = -159393048720015715L;

    private String username;
}
