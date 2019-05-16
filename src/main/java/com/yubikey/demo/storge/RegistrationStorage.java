package com.yubikey.demo.storge;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.data.ByteArray;
import com.yubikey.demo.entry.CredentialRegistration;
import com.yubikey.demo.entry.UserEntry;

import java.util.Collection;
import java.util.Optional;

public interface RegistrationStorage extends CredentialRepository {


    /**
     * 注册用户
     * @param userEntry
     * @return
     */
    boolean addRegistrationByUser(UserEntry userEntry);


    Collection<UserEntry> getUserEntryByUsername(String username);
    /**
     * 通过用户名获取注册凭证
     * @param username
     * @return
     */
    Collection<CredentialRegistration> getRegistrationsByUsername(String username);

    /**
     * 获取用户信息
     * @param username
     * @param credentialId
     * @return
     */
    Optional<UserEntry> getUserEntryByUsernameAndCredentialId(String username, ByteArray credentialId);


    /**
     * 根据用户名删除用户凭证
     * @param username
     * @param userEntry
     * @return
     */
    boolean removeRegistrationByUsername(String username, UserEntry userEntry);

    /**
     * 根据用户名删除用户凭证
     * @param username
     * @return
     */
    boolean removeAllRegistrations(String username);

    /**
     * 变更签名验证次数
     * @param username
     * @param credentialId
     * @param signatureCount
     */
    void updateSignatureCount(String username, ByteArray credentialId, long signatureCount);
}
