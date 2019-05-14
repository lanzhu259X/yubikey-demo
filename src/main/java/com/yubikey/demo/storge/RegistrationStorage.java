package com.yubikey.demo.storge;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.ByteArray;
import com.yubikey.demo.entry.CredentialRegistration;

import java.util.Collection;
import java.util.Optional;

public interface RegistrationStorage extends CredentialRepository {

    /**
     * 通过用户名注册
     * @param username
     * @param reg
     * @return
     */
    boolean addRegistrationByUsername(String username, CredentialRegistration reg);

    /**
     * 通过用户名获取注册凭证
     * @param username
     * @return
     */
    Collection<CredentialRegistration> getRegistrationsByUsername(String username);

    /**
     * 通过用户名和用户句柄获取注册凭证
     * @param username
     * @param userHandle
     * @return
     */
    Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, ByteArray userHandle);

    /**
     * 获取用户句柄获取注册凭证集
     * @param userHandle
     * @return
     */
    Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle);

    /**
     * 根据用户名删除用户凭证
     * @param username
     * @param credentialRegistration
     * @return
     */
    boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration);

    /**
     * 根据用户名删除用户凭证
     * @param username
     * @return
     */
    boolean removeAllRegistrations(String username);

    /**
     * 变更签名验证次数
     * @param result
     */
    void updateSignatureCount(AssertionResult result);
}
