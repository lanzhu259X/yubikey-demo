package com.yubikey.demo.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.meta.VersionInfo;
import com.yubikey.demo.service.YubiKeyService;
import com.yubikey.demo.vo.RegistrationRequest;
import com.yubikey.demo.vo.U2fRegistrationRequest;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@Log4j2
@RestController
public class YubiKeyAuthController {

    @Autowired
    private YubiKeyService yubiKeyService;

    private static final ObjectMapper jsonMapper = WebAuthnCodecs.json();

    private <T> JSONObject parseToResult(T result) {
        try {
            return JSON.parseObject(jsonMapper.writeValueAsString(result));
        }catch (Exception e) {
            log.error("parse to json Fail. ", e);
            throw new RuntimeException("Result parse to json fail.");
        }
    }

    @GetMapping("/version")
    public JSONObject getVersion() {
        VersionInfo versionInfo = VersionInfo.getInstance();
        return parseToResult(versionInfo);
    }

    @PostMapping("/register-start")
    public JSONObject startRegistration(@RequestBody RegistrationRequest request) {
        String username = request.getUsername();
        String displayName = request.getDisplayName();
        String credentialNickname = request.getCredentialNickname();
        boolean requireResidentKey = request.isRequireResidentKey();
        log.info("start registration request:{} ", JSON.toJSONString(request));
        RegistrationRequest result = yubiKeyService.startRegistration(username, displayName, credentialNickname, requireResidentKey);
        return parseToResult(result);
    }

    @PostMapping("/register-u2f-finish")
    public JSONObject finishU2fRegistration(@RequestBody U2fRegistrationRequest request) {
        log.info("register-finish :{}", JSON.toJSONString(request));
        JSONObject response = new JSONObject();
        try {
            boolean result = yubiKeyService.finishU2fRegistration(request);
            response.put("SUCCESS", true);
        }catch (Exception e) {
            response.put("SUCCESS", false);
            response.put("MESSAGE", e.toString());
        }
        return response;
    }




}
