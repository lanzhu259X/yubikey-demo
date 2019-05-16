package com.yubikey.demo.storge;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubikey.demo.entry.CredentialRegistration;
import com.yubikey.demo.entry.UserEntry;
import lombok.extern.log4j.Log4j2;

import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Log4j2
public class MemoryRegistrationStorage implements RegistrationStorage, CredentialRepository {

    /**
     * 存储信息（username为key, 存储的时允许一个username 存在多个绑定值
     */
    private final Cache<String, Set<UserEntry>> storage = CacheBuilder
            .newBuilder()
            .maximumSize(1000)
            .expireAfterAccess(1, TimeUnit.DAYS)
            .build();

    @Override
    public boolean addRegistrationByUser(UserEntry userEntry) {
        try {
            return storage.get(userEntry.getUsername(), HashSet::new).add(userEntry);
        }catch (ExecutionException e) {
            log.error("Fail to add Registration, username:{} ", userEntry.getUsername(), e);
            throw new RuntimeException(e);
        }
    }

    public Collection<UserEntry> getUserEntryByUsername(String username) {
        try {
            return storage.get(username, HashSet::new);
        }catch (ExecutionException e){
            log.error("Fail to get by username:{}", username, e);
            throw new RuntimeException("user not exist");
        }
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUsername(String username) {
        try {
            Collection<UserEntry> userEntries = storage.get(username, HashSet::new);
            return userEntries.stream().map(UserEntry::getCredentialRegistration).collect(Collectors.toSet());
        }catch (Exception e) {
            log.error("Fail to get by username:{}", username, e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<UserEntry> getUserEntryByUsernameAndCredentialId(String username, ByteArray credentialId) {
        if (credentialId == null || credentialId.isEmpty()) {
            return Optional.empty();
        }
        try {
            return storage.get(username, HashSet::new).stream()
                    .filter(item -> credentialId.equals(item.getCredentialId()))
                    .findFirst();
        }catch (Exception e) {
            log.error("UserEntry lookup failed. username:{} id:{}", username, credentialId, e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean removeRegistrationByUsername(String username, UserEntry userEntry) {
        try {
            return storage.get(username, HashSet::new).remove(userEntry);
        }catch (Exception e) {
            log.error("Fail to remove regisration username:{}", username);
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean removeAllRegistrations(String username) {
        storage.invalidate(username);
        return true;
    }

    @Override
    public void updateSignatureCount(String username, ByteArray credentialId, long signatureCount) {
        Optional<UserEntry> userEntries = getUserEntryByUsername(username).stream()
                .filter(item -> credentialId.equals(item.getCredentialId()))
                .findFirst();
        if (userEntries.isPresent()) {

        }else {
            throw new RuntimeException(String.format("Credential %s is not registered to username %s", credentialId, username));
        }
        Set<UserEntry> entries = storage.getIfPresent(username);
        UserEntry userEntry = userEntries.get();
        entries.remove(userEntry);
        userEntry.setSignatureCount(signatureCount);
        entries.add(userEntry);
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return getUserEntryByUsername(username).stream().findAny().map(item -> item.getUserHandle());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(item -> userHandle.equals(item.getUserHandle()))
                .findAny()
                .map(UserEntry::getUsername);
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return getRegistrationsByUsername(username).stream()
                .map(credentialRegistration -> PublicKeyCredentialDescriptor.builder()
                        .id(credentialRegistration.getCredential().getCredentialId()).build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Optional<UserEntry> userEntryMybe = storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(userEntry -> credentialId.equals(userEntry.getCredentialId()))
                .findAny();
        return userEntryMybe.flatMap(userEntry -> Optional.of(userEntry.getRegisteredCredential()));
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return CollectionUtil.immutableSet(
                storage.asMap().values().stream()
                        .flatMap(Collection::stream)
                        .filter(userEntry -> userEntry.getCredentialId().equals(credentialId))
                        .map(UserEntry::getRegisteredCredential)
                        .collect(Collectors.toSet())
        );
    }

}
