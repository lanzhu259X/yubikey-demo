package com.yubikey.demo;

import lombok.Data;

import java.io.Serializable;

@Data
public class UserModel implements Serializable {

    private static final long serialVersionUID = 8665685909853529258L;

    private Integer userId;

    private long signatureCount;

    private String credential;
}
