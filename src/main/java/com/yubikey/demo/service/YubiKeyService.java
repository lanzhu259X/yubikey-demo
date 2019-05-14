package com.yubikey.demo.service;

import com.alibaba.fastjson.JSONObject;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.U2fVerifier;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubikey.demo.entry.CredentialRegistration;
import com.yubikey.demo.storge.MemoryRegistrationStorage;
import com.yubikey.demo.storge.RegistrationStorage;
import com.yubikey.demo.vo.RegistrationRequest;
import com.yubikey.demo.vo.U2fCredential;
import com.yubikey.demo.vo.U2fCredentialResponse;
import com.yubikey.demo.vo.U2fRegistrationRequest;
import lombok.NonNull;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Log4j2
@Service
public class YubiKeyService {

    private static final String RELY_PART_ID = "yubikey.demo";
    private static final String RELY_PART_NAME = "yubikey.demo";
    private static final String APP_ID = "https://localhost:10000";

    private static final SecureRandom random = new SecureRandom();
    private final Clock clock = Clock.systemUTC();

    private RelyingParty rp;

    private RegistrationStorage userStorage;
    private Cache<ByteArray, RegistrationRequest> registerRequestStorage;

    private static <K, V> Cache<K, V> newCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(100)
                .expireAfterAccess(10, TimeUnit.MINUTES)
                .build();
    }

    @PostConstruct
    public void init() {
        log.info("=======> init service");
        try {
            this.userStorage = new MemoryRegistrationStorage();
            this.registerRequestStorage = newCache();

            RelyingPartyIdentity relyingPartyIdentity = RelyingPartyIdentity.builder()
                    .id(RELY_PART_ID)
                    .name(RELY_PART_NAME)
                    .build();

            rp = RelyingParty.builder()
                    .identity(relyingPartyIdentity)
                    .credentialRepository(this.userStorage)
                    .appId(new AppId(APP_ID))
                    .validateSignatureCounter(true)
                    .build();
            log.info("======> init RelyingParty :{}", rp);
        }catch (Exception e) {
            log.error("init error ", e);
        }
    }

    private static ByteArray geneateRandom(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    /**
     * 开始申请注册信息
     * @param username
     * @param displayName
     * @param credentialNickname
     * @param requireResidentKey
     * @return
     */
    public RegistrationRequest startRegistration(@NonNull String username, @NonNull String displayName, String credentialNickname, boolean requireResidentKey) {
        log.info("startRegistraion username:{} credentialNickname:{}", username, credentialNickname);
        JSONObject result = new JSONObject();
        if (!userStorage.getRegistrationsByUsername(username).isEmpty()) {
            throw new RuntimeException("The username is already registered");
        }
        RegistrationRequest request = new RegistrationRequest();
        request.setUsername(username);
        request.setCredentialNickname(credentialNickname);
        request.setRequestId(geneateRandom(32));

        UserIdentity identity = UserIdentity.builder()
                .name(username)
                .displayName(displayName)
                .id(geneateRandom(32))
                .build();
        StartRegistrationOptions options = StartRegistrationOptions.builder()
                .user(identity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder().requireResidentKey(requireResidentKey).build())
                .build();
        PublicKeyCredentialCreationOptions creationOptions = rp.startRegistration(options);
        request.setPublicKeyCredentialCreationOptions(creationOptions);

        // 存入缓存，方便完成验证的时候检查是否存在该请求
        registerRequestStorage.put(request.getRequestId(), request);
        return request;
    }

    /**
     * 完成  U2F 注册
     * @param request
     * @return
     */
    public boolean finishU2fRegistration(U2fRegistrationRequest request) {
        RegistrationRequest registrationRequest = registerRequestStorage.getIfPresent(request.getRequestId());
        registerRequestStorage.invalidate(request.getRequestId());
        if (registrationRequest == null) {
            log.warn("requestId ERROR. {}", request.getRequestId());
            throw new RuntimeException("RequestId ERROR");
        }
        // 对参数进行验签
        try {
            if (!U2fVerifier.verify(rp.getAppId().get(), registrationRequest, request)) {
                log.warn("参数验签失败. requestId:{}", request.getRequestId());
                throw new RuntimeException("Fail to verify signature");
            }
        }catch (Exception e) {
            log.error("Fail to verify U2F signature.", e);
            throw new RuntimeException("Fail to verify U2F signature");
        }
        UserIdentity userIdentity = registrationRequest.getPublicKeyCredentialCreationOptions().getUser();
        String nickname = registrationRequest.getCredentialNickname();
        addRegistration(userIdentity, Optional.of(nickname), 0, request.getCredential().getU2fResponse());
        return true;
    }


    private CredentialRegistration addRegistration(
            UserIdentity userIdentity,
            Optional<String> nickname,
            long signatureCount,
            U2fCredentialResponse u2fCredentialResponse
    ) {

        PublicKeyCredentialDescriptor descriptor = PublicKeyCredentialDescriptor.builder().id(u2fCredentialResponse.getKeyHandle()).build();
        ByteArray publicKeyCose = WebAuthnCodecs.rawEcdaKeyToCose(u2fCredentialResponse.getPublicKey());

        RegisteredCredential credential = RegisteredCredential.builder()
                .credentialId(descriptor.getId())
                .userHandle(userIdentity.getId())
                .publicKeyCose(publicKeyCose)
                .signatureCount(signatureCount)
                .build();

        CredentialRegistration reg = CredentialRegistration.builder()
                .userIdentity(userIdentity)
                .credentialNickname(nickname)
                .registrationTime(new Date())
                .credential(credential)
                .signatureCount(signatureCount)
                .attestationMetadata(Optional.empty())
                .build();

        log.info(
                "Adding registration: user: {}, nickname: {}, credential: {}",
                userIdentity,
                nickname,
                credential
        );
        userStorage.addRegistrationByUsername(userIdentity.getName(), reg);
        return reg;
    }

}
