package com.yubikey.demo;

import com.alibaba.fastjson.JSONObject;
import com.yubico.webauthn.meta.VersionInfo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class YubiKeyAuthController {

    @GetMapping("/version")
    public JSONObject getVersion() {
        VersionInfo versionInfo = VersionInfo.getInstance();
        JSONObject result = new JSONObject();
        result.put("data", versionInfo);
        return result;
    }




}
