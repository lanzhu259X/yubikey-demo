package com.yubikey.demo.storge;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubikey.demo.entry.CredentialRegistration;
import lombok.extern.log4j.Log4j2;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Log4j2
public class MemoryRegistrationStorage implements RegistrationStorage, CredentialRepository {

    /**
     * 存储信息
     */
    private final Cache<String, Set<CredentialRegistration>> storage = CacheBuilder
            .newBuilder()
            .maximumSize(1000)
            .expireAfterAccess(1, TimeUnit.DAYS)
            .build();

    @Override
    public boolean addRegistrationByUsername(String username, CredentialRegistration reg) {
        try {
            return storage.get(username, HashSet::new).add(reg);
        }catch (Exception e) {
            log.error("Fail to add Registration, username:{} ", username, e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUsername(String username) {
        try {
            return storage.get(username, HashSet::new);
        }catch (Exception e) {
            log.error("Fail to get by username:{}", username, e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<CredentialRegistration> getRegistrationByUsernameAndCredentialId(String username, ByteArray id) {
        if (id == null || id.isEmpty()) {
            return Optional.empty();
        }
        try {
            return storage.get(username, HashSet::new).stream()
                    .filter(item -> id.equals(item.getCredential().getCredentialId()))
                    .findFirst();
        }catch (Exception e) {
            log.error("Registration lookup failed. username:{} id:{}", username, id, e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUserHandle(ByteArray userHandle) {
        if (userHandle == null || userHandle.isEmpty()) {
            return Collections.emptyList();
        }
        return storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(credentialRegistration -> userHandle.equals(credentialRegistration.getUserIdentity().getId()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean removeRegistrationByUsername(String username, CredentialRegistration credentialRegistration) {
        try {
            return storage.get(username, HashSet::new).remove(credentialRegistration);
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
    public void updateSignatureCount(AssertionResult result) {
        CredentialRegistration registration = getRegistrationByUsernameAndCredentialId(result.getUsername(), result.getCredentialId())
                .orElseThrow(() -> new NoSuchElementException(
                        String.format("Credential %s is not registered to user %s", result.getCredentialId(), result.getUsername())));
        Set<CredentialRegistration> regs = storage.getIfPresent(result.getUsername());
        regs.remove(registration);
        registration.setSignatureCount(result.getSignatureCount());
        regs.add(registration);
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return getRegistrationsByUsername(username).stream()
                .map(credentialRegistration -> PublicKeyCredentialDescriptor.builder()
                    .id(credentialRegistration.getCredential().getCredentialId()).build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String s) {
        return Optional.empty();
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray byteArray) {
        return Optional.empty();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Optional<CredentialRegistration> registrationMaybe = storage.asMap().values().stream()
                .flatMap(Collection::stream)
                .filter(creReg -> credentialId.equals(creReg.getCredential().getCredentialId()))
                .findAny();
        return registrationMaybe.flatMap(registration -> Optional.of(
                RegisteredCredential.builder()
                .credentialId(registration.getCredential().getCredentialId())
                .userHandle(registration.getUserIdentity().getId())
                .publicKeyCose(registration.getCredential().getPublicKeyCose())
                .signatureCount(registration.getSignatureCount())
                .build()
        ));
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return CollectionUtil.immutableSet(
                storage.asMap().values().stream()
                        .flatMap(Collection::stream)
                        .filter(reg -> reg.getCredential().getCredentialId().equals(credentialId))
                        .map(reg -> RegisteredCredential.builder()
                                .credentialId(reg.getCredential().getCredentialId())
                        .userHandle(reg.getUserIdentity().getId())
                        .publicKeyCose(reg.getCredential().getPublicKeyCose())
                        .signatureCount(reg.getSignatureCount())
                        .build()).collect(Collectors.toSet())
        );
    }
}
