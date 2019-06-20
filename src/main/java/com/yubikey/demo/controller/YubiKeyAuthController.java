package com.yubikey.demo.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.meta.VersionInfo;
import com.yubikey.demo.service.U2FService;
import com.yubikey.demo.service.YubiKeyService;
import com.yubikey.demo.vo.*;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
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
    @Autowired
    private U2FService u2FService;

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
    public JSONObject startRegistration(@RequestBody RegistrationStartRequest request) {
        String username = request.getUsername();
        String credentialNickname = request.getCredentialNickname();
        log.info("start registration request:{} ", JSON.toJSONString(request));
        RegistrationResponse result = yubiKeyService.startRegistration(username, credentialNickname);
        return parseToResult(result);
    }

    @PostMapping("/register-finish")
    public JSONObject finishRegistration(@RequestBody String request) {
        log.info("register-finish :{}", request);
        JSONObject response = new JSONObject();
        try {
            RegistrationFinishRequest finishRequest = jsonMapper.readValue(request, RegistrationFinishRequest.class);
            boolean result = yubiKeyService.finishRegistration(finishRequest);
            response.put("SUCCESS", result);
        }catch (Exception e) {
            response.put("SUCCESS", false);
            response.put("MESSAGE", e.toString());
        }
        return response;
    }


    @PostMapping("/authenticate-start")
    public JSONObject startAuthenticate(@RequestBody AuthenticateStartRequest request) {
        String username = request.getUsername();
        if (StringUtils.isBlank(username)) {
            throw new RuntimeException("Username miss");
        }
        log.info("username {} request start authenticate.", username);
        AuthenticateStartResponse response = yubiKeyService.startAuthenticate(username);
        return parseToResult(response);
    }

    @PostMapping("/authenticate-finish")
    public JSONObject finishAuthenticate(@RequestBody String request) {
        log.info("authenticate-finish :{}", request);
        JSONObject response = new JSONObject();
        try {
            AssertionFinishRequest assertionFinishRequest = jsonMapper.readValue(request, AssertionFinishRequest.class);
            boolean result = yubiKeyService.finishAuthentication(assertionFinishRequest);
            response.put("result", result);
        }catch (Exception e ){
            log.error("error ", e);
            response.put("result", false);
            response.put("message", e.getMessage());
        }
        return response;
    }


    @PostMapping("/deregister")
    public JSONObject deregisterCredential(@RequestBody DeregisterCredentialRequest request) {
        log.info("request deregister credential. username:{}", request.getUsername());
        final ByteArray credentialId;
        try {
            if (StringUtils.isBlank(request.getCredentialIdBase64())) {
                credentialId = null;
            }else {
                credentialId = ByteArray.fromBase64Url(request.getCredentialIdBase64());
            }
        }catch (Base64UrlException e) {
            throw new RuntimeException("credential id is not valid Base64Url data");
        }
        boolean result = yubiKeyService.deregisterCredential(request.getUsername(), credentialId);
        JSONObject response = new JSONObject();
        response.put("result", result);
        return response;
    }

    @PostMapping("/u2f/startRegister")
    public JSONObject u2fStartRegister(@RequestBody U2FRequest registerRequest) throws Exception {
        log.info("u2f start register:{}", JSON.toJSONString(registerRequest));
        U2FRegisterResponse response = u2FService.startRegistration(registerRequest.getUsername());
        return parseToResult(response);
    }

    @PostMapping("/u2f/finishRegister")
    public JSONObject u2fFinishRegister(@RequestBody U2FFinishRequest request) throws Exception {
        log.info("u2f finish register:{}", JSON.toJSONString(request));
        JSONObject map = new JSONObject();
        try {
            boolean result = u2FService.finishRegistration(request.getTokenResponse(), request.getUsername());
            map.put("result", result);
        }catch (Exception e) {
            map.put("result", false);
            map.put("MESSAGE", e.getMessage());
        }
        return map;
    }

    @PostMapping("/u2f/startAuthentication")
    public JSONObject u2fStartAuthentication(@RequestBody U2FRequest request) {
        log.info("u2f start authentication :{}", JSON.toJSONString(request));
        U2FStartAuthResponse response = u2FService.startAuthentication(request.getUsername());
        return parseToResult(response);
    }

    @PostMapping("/u2f/finishAuthentication")
    public JSONObject u2fFinishAuthentication(@RequestBody U2FFinishRequest request) throws Exception {
        log.info("u2f finish Authentication:{}", JSON.toJSONString(request));
        JSONObject map = new JSONObject();
        try {
            boolean result = u2FService.finishAuthentication(request.getTokenResponse(), request.getUsername());
            map.put("result", result);
        }catch (Exception e) {
            map.put("result", false);
            map.put("MESSAGE", e.getMessage());
        }
        return map;
    }

}
