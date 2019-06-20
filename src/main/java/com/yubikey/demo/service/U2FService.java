package com.yubikey.demo.service;

import com.yubico.u2f.U2F;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.data.messages.SignRequestData;
import com.yubico.u2f.data.messages.SignResponse;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.U2fAuthenticationException;
import com.yubico.u2f.exceptions.U2fRegistrationException;
import com.yubikey.demo.entry.U2FEntry;
import com.yubikey.demo.vo.U2FRegisterResponse;
import com.yubikey.demo.vo.U2FStartAuthResponse;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Log4j2
@Service
public class U2FService {

    private static final String APP_ID = "https://mytest.com";

    private final Map<String, String> requestStorage = new HashMap<>();

    private final Map<String, Set<U2FEntry>> userStorage = new HashMap<>();

    private final U2F u2F = new U2F();

    private U2FEntry buildByDeviceRegistration(String username, DeviceRegistration registration) throws Exception {
        if (StringUtils.isBlank(username) || registration == null) {
            return null;
        }
        U2FEntry entry = new U2FEntry();
        entry.setUsername(username);
        entry.setKeyHandle(registration.getKeyHandle());
        entry.setCompromised(registration.isCompromised());
        entry.setCounter(registration.getCounter());
        entry.setPublicKey(registration.getPublicKey());
        X509Certificate certificate = registration.getAttestationCertificate();
        if (certificate != null) {
            entry.setAttestationCert(U2fB64Encoding.encode(certificate.getEncoded()));
        }else {
            entry.setAttestationCert(null);
        }
        return entry;
    }

    private DeviceRegistration buildByU2FEntry(U2FEntry u2FEntry) throws Exception {
        return new DeviceRegistration(u2FEntry.getKeyHandle(), u2FEntry.getPublicKey(), u2FEntry.getAttestationCert(), u2FEntry.getCounter(), u2FEntry.isCompromised());
    }

    public U2FRegisterResponse startRegistration(String username) throws Exception {
        Set<U2FEntry> u2FEntrySet = userStorage.get(username);
        if (u2FEntrySet == null ) {
            u2FEntrySet = new HashSet<>();
        }
        Set<DeviceRegistration> deviceRegistrations = new HashSet<>();
        for (U2FEntry entry : u2FEntrySet) {
            deviceRegistrations.add(buildByU2FEntry(entry));
        }
        RegisterRequestData registerRequestData = u2F.startRegistration(APP_ID, deviceRegistrations);
        requestStorage.put(registerRequestData.getRequestId(), registerRequestData.toJson());
        return new U2FRegisterResponse(username, registerRequestData.toJson());
    }

    public Boolean finishRegistration(String response, String username) throws Exception {
        RegisterResponse registerResponse = RegisterResponse.fromJson(response);
        RegisterRequestData registerRequestData = RegisterRequestData.fromJson(requestStorage.remove(registerResponse.getRequestId()));
        boolean result = false;
        try {
            DeviceRegistration registration = u2F.finishRegistration(registerRequestData, registerResponse);
            log.info("user:{} register u2f registration:{}", username, registration.toJson());
            U2FEntry entry = buildByDeviceRegistration(username, registration);
            Set<U2FEntry> entries = userStorage.get(username);
            if (entries == null) {
                entries = new HashSet<>();
            }
            entries.add(entry);
            userStorage.put(username, entries);
            result = true;
        }catch (U2fRegistrationException e) {
            log.info("register fail username:{}, response{}", username, response);
            result = false;
        }
        return result;
    }

    public U2FStartAuthResponse startAuthentication(String username) {
        Set<U2FEntry> entrys = userStorage.get(username);
        if (entrys == null || entrys.isEmpty()) {
            log.info("username is not register: username:{}", username);
            throw new RuntimeException("Username " + username + " not register.");
        }
        try {
            Set<DeviceRegistration> registrations = new HashSet<>();
            for (U2FEntry entry : entrys) {
                registrations.add(buildByU2FEntry(entry));
            }
            SignRequestData signRequestData = u2F.startSignature(APP_ID, registrations);
            log.info("username start authentication: {} data:{}", username, signRequestData.toJson());
            requestStorage.put(signRequestData.getRequestId(), signRequestData.toJson());
            return new U2FStartAuthResponse(username, signRequestData.toJson());
        }catch (Exception e) {
            log.error("start authentication fail. username:{}", username);
            throw new RuntimeException("start authentication fail username:" + username);
        }
    }

    public Boolean finishAuthentication(String response, String username) throws Exception {
        SignResponse signResponse = SignResponse.fromJson(response);
        SignRequestData signRequestData = SignRequestData.fromJson(requestStorage.get(signResponse.getRequestId()));
        DeviceRegistration registration = null;
        boolean result = true;
        Set<U2FEntry> entrys = userStorage.get(username);
        if (entrys == null || entrys.isEmpty()) {
            log.info("username is not register: username:{}", username);
            throw new RuntimeException("Username " + username + " not register.");
        }
        try {
            Set<DeviceRegistration> registrations = new HashSet<>();
            for (U2FEntry u2FEntry : entrys) {
                registrations.add(buildByU2FEntry(u2FEntry));
            }
            registration = u2F.finishSignature(signRequestData, signResponse, registrations);
        }catch (DeviceCompromisedException e) {
            registration = e.getDeviceRegistration();
            log.warn("Device possibly compromised and therefore blocked: {} {}", username, e.getMessage());
            result = false;
        }catch (U2fAuthenticationException e) {
            log.warn("authentication fail username:{}", username);
            result = false;
        }finally {
            U2FEntry u2FEntry = buildByDeviceRegistration(username, registration);
            if (u2FEntry != null) {
                entrys.add(u2FEntry);
                userStorage.put(username, entrys);
            }
        }
        return result;
    }


}
