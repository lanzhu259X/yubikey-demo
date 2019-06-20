package com.yubikey.demo.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class U2FStartAuthResponse {

    private String username;
    private String data;


}
