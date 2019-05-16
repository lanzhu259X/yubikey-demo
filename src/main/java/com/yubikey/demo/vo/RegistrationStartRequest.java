package com.yubikey.demo.vo;

import lombok.Data;
import lombok.NonNull;

import java.io.Serializable;

@Data
public class RegistrationStartRequest implements Serializable {

    private static final long serialVersionUID = 4795768082489208979L;

    @NonNull
    private String username;

    @NonNull
    private String credentialNickname;

}
