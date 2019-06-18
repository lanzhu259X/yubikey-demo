package com.yubikey.demo.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubikey.demo.entry.UserEntry;
import com.yubikey.demo.storge.MemoryRegistrationStorage;
import com.yubikey.demo.storge.RegistrationStorage;
import com.yubikey.demo.util.YubicoHelper;
import com.yubikey.demo.vo.*;
import lombok.NonNull;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Log4j2
@Service
public class YubiKeyService {

    /**
     * 发现需要与域名段保存一致
     */
    private static final String RELY_PART_ID = "mytest.com";
    private static final String RELY_PART_NAME = "Yubico WebAuthn demo";
    /**
     * 需要与请求源的域名信息一致，使用的源请求必须要使用https证书方式，
     * 如果localhost下没有用https方式，则无法进行验证。
     * 测试时改为自己的https证书的域名
     */
    private static final String APP_ID = "https://mytest.com";

    private static final String ORIGINS = "https://mytest.com,https://jacktest.com";
    private RelyingParty rp;

    private RegistrationStorage userStorage;
    private Cache<ByteArray, RegistrationResponse> registerRequestStorage;
    private Cache<ByteArray, AuthenticateStartResponse> assertionRequestStorage;

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
            this.assertionRequestStorage = newCache();

            RelyingPartyIdentity relyingPartyIdentity = RelyingPartyIdentity.builder()
                    .id(RELY_PART_ID)
                    .name(RELY_PART_NAME)
                    .build();
            // 注意需要注入可信任来源信息
            Set<String> origins = new HashSet<>(Arrays.asList(ORIGINS.split(",")));

            /*
             * 注意name是必需的, id(RelyingPartyIdentity)属性必须等于客户端看到的原始域，或者origin必须是id的子域。如果省略id，则使用originins有效域。
             */
            rp = RelyingParty.builder()
                    .identity(relyingPartyIdentity)
                    .credentialRepository(this.userStorage)
                    .appId(new AppId(APP_ID))
                    .validateSignatureCounter(true)
                    .origins(origins)
                    .build();
            log.info("======> init RelyingParty :{}", rp);
        }catch (Exception e) {
            log.error("init error ", e);
        }
    }

    /**
     * 开始申请注册信息
     * @param username
     * @param credentialNickname
     * @return
     */
    public RegistrationResponse startRegistration(@NonNull String username, @NonNull String credentialNickname) {
        log.info("startRegistraion username:{} credentialNickname:{}", username, credentialNickname);
        JSONObject result = new JSONObject();
        Collection<UserEntry> userEntries = userStorage.getUserEntryByUsername(username);
        if (!userEntries.isEmpty()) {
            for (UserEntry userEntry : userEntries) {
                if (credentialNickname.equals(userEntry.getNickname())) {
                    throw new RuntimeException("The username is already registered");
                }
            }
        }
        UserIdentity identity = UserEntry.generateUserIdentity(username, credentialNickname);
        StartRegistrationOptions options = StartRegistrationOptions.builder()
                .user(identity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder().requireResidentKey(false).build())
                .build();
        PublicKeyCredentialCreationOptions creationOptions = rp.startRegistration(options);

        RegistrationResponse response = RegistrationResponse.builder()
                .requestId(YubicoHelper.geneateRandom(32))
                .username(username)
                .appId(APP_ID)
                .credentialNickname(credentialNickname)
                .publicKeyCredentialCreationOptions(creationOptions)
                .build();

        // 存入缓存，方便完成验证的时候检查是否存在该请求
        registerRequestStorage.put(response.getRequestId(), response);
        return response;
    }

    /**
     * 完成  U2F 注册
     * @param request
     * @return
     */
    public boolean finishRegistration(RegistrationFinishRequest request) {
        RegistrationResponse registrationResponse = registerRequestStorage.getIfPresent(request.getRequestId());
        registerRequestStorage.invalidate(request.getRequestId());
        if (registrationResponse == null) {
            log.warn("requestId ERROR. {}", request.getRequestId());
            throw new RuntimeException("RequestId ERROR");
        }
        // 对参数进行验签
        try {
            FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                    .request(registrationResponse.getPublicKeyCredentialCreationOptions())
                    .response(request.getCredential())
                    .build();
            RegistrationResult registrationResult = rp.finishRegistration(options);

            UserIdentity userIdentity = registrationResponse.getPublicKeyCredentialCreationOptions().getUser();
            String nickname = registrationResponse.getCredentialNickname();
            long signatureCount = request.getCredential().getResponse().getAttestation().getAuthenticatorData().getSignatureCounter();
            ByteArray userHandler = userIdentity.getId();
            ByteArray credentialId = registrationResult.getKeyId().getId();
            ByteArray publicKey = registrationResult.getPublicKeyCose();

            // 创建一个用户信息并保存
            UserEntry userEntry = UserEntry.builder()
                    .username(userIdentity.getName())
                    .nickname(nickname)
                    .signatureCount(signatureCount)
                    .credentialId(credentialId)
                    .userHandle(userHandler)
                    .publicKey(publicKey)
                    .registerTime(new Date())
                    .build();
            userStorage.addRegistrationByUser(userEntry);
            return true;
        }catch (Exception e) {
            log.error("Fail to verify signature.", e);
            throw new RuntimeException("Fail to verify signature");
        }
    }

    /**
     * 申请验证
     * @param username
     * @return
     */
    public AuthenticateStartResponse startAuthenticate(String username) {
        log.info("username {}  request start-authenticate.", username);
        if (StringUtils.isBlank(username)) {
            throw new RuntimeException("authenticate username miss");
        }
        Collection<UserEntry> userEntry = userStorage.getUserEntryByUsername(username);
        if (userEntry == null || userEntry.isEmpty()) {
            throw new RuntimeException("username not register.");
        }
        AssertionRequest request = rp.startAssertion(
                StartAssertionOptions.builder()
                    .username(username).build()
        );
        AuthenticateStartResponse startResponse = AuthenticateStartResponse.builder()
                .requestId(YubicoHelper.geneateRandom(32))
                .request(request)
                .username(username)
                .publicKeyCredentialRequestOptions(request.getPublicKeyCredentialRequestOptions())
                .build();
        // 把请求信息保存再缓存中
        assertionRequestStorage.put(startResponse.getRequestId(), startResponse);
        return startResponse;
    }

    /**
     * 结束验证
     * @param assertionFinishRequest
     * @return
     */
    public boolean finishAuthentication(AssertionFinishRequest assertionFinishRequest) {
        ByteArray requestId = assertionFinishRequest.getRequestId();
        if (requestId == null) {
            throw new RuntimeException("RequestId miss");
        }
        log.info("finish authentication request params:{}", JSON.toJSONString(assertionFinishRequest));
        AuthenticateStartResponse startResponse = assertionRequestStorage.getIfPresent(requestId);
        assertionRequestStorage.invalidate(requestId);
        if (startResponse == null) {
            throw new RuntimeException("RequestId expired");
        }
        boolean deregister = assertionFinishRequest.isDeregister();
        String username = startResponse.getUsername();
        try {
            /*
               注意点，在google 浏览器的70.xxx 版本之后，会有个问题就是获取到的 userHandler是空串"", 这时候解析出来的
               userHandler是存在有值的，在对比时会出现不相等的错误，参考：https://github.com/Yubico/java-webauthn-server/issues/12
               解决方案：1. 由前端在请求前判断该参数值，如果是空串则设置为null, 2. 后端判断，在拿到该值时，如果存在并且为空串，
               则设置为不存在的情况, 这时候对比的源会从数据存储中获取该用户的userHandler, 对比参考点：FinishAssertionSteps.Step0 的 userHandler 初始化
             */
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential = assertionFinishRequest.getCredential();
            Optional<ByteArray> userHandler = credential.getResponse().getUserHandle();
            if (userHandler.isPresent() && userHandler.get().isEmpty()) {
                AuthenticatorAssertionResponse authenticatorAssertionResponse = credential.getResponse().toBuilder().userHandle(Optional.empty()).build();
                credential = credential.toBuilder().response(authenticatorAssertionResponse).build();
            }
            ByteArray credentialId = credential.getId();
            FinishAssertionOptions finishAssertionOptions = FinishAssertionOptions.builder()
                    .request(startResponse.getRequest())
                    .response(credential)
                    .build();
            AssertionResult result = rp.finishAssertion(finishAssertionOptions);
            if (result.isSuccess()) {

                try {
                    if (deregister) {
                        // 如果是注销操作，验证成功后直接删除用户信息
                        deregisterCredential(username, credentialId);
                    }else {
                        // 验证成功时，变更计数
                        userStorage.updateSignatureCount(result.getUsername(), result.getCredentialId(), result.getSignatureCount());
                    }
                }catch (Exception e) {
                    log.error("Fail to update signture count for user:{} credential:{}", result.getUsername(), assertionFinishRequest.getCredential().getId(), e);
                }
                return true;
            }else {
                return false;
            }
        }catch (AssertionFailedException e) {
            log.error("Assertion failed requestId:{}", requestId, e);
            return false;
        }catch (Exception e) {
            log.error("Assertion failed exception. requestId:{}", requestId, e);
            return false;
        }
    }

    /**
     * 注销
     * @param username
     * @param credentialId
     * @return
     */
    public boolean deregisterCredential(String username, ByteArray credentialId) {
        log.info("deregisterCredential username:{} credentialId:{}", username, credentialId);
        if (StringUtils.isBlank(username)) {
            throw new RuntimeException("username miss");
        }
        boolean result = false;
        if (credentialId == null || credentialId.isEmpty()) {
            result = userStorage.removeAllRegistrations(username);
        }else {
            Optional<UserEntry> userEntryReg = userStorage.getUserEntryByUsernameAndCredentialId(username, credentialId);
            if (userEntryReg.isPresent()) {
                result = userStorage.removeRegistrationByUsername(username, userEntryReg.get());
            }else {
                throw new RuntimeException(String.format("Credential ID not registered. username %s credential %s", username, credentialId));
            }
        }
        return result;
    }
}
