package com.yubikey.demo.entry;

import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import com.yubikey.demo.util.YubicoHelper;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;
import java.util.Optional;

@Builder
@Setter
@Getter
public class UserEntry implements Serializable {

    private static final long serialVersionUID = -6694482451555164999L;

    private String username;

    private String nickname;

    private ByteArray credentialId;

    private ByteArray userHandle;

    private ByteArray publicKey;

    private long signatureCount;

    private Date registerTime;

    public static UserIdentity generateUserIdentity(String username, String nickname) {
        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(nickname)
                .id(YubicoHelper.geneateRandom(32))
                .build();
        return userIdentity;
    }

    public UserIdentity getUserIdentity() {
        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(nickname)
                .id(userHandle)
                .build();
        return userIdentity;
    }

    public RegisteredCredential getRegisteredCredential() {
        RegisteredCredential credential = RegisteredCredential.builder()
                .credentialId(credentialId)
                .userHandle(userHandle)
                .publicKeyCose(publicKey)
                .signatureCount(signatureCount)
                .build();
        return credential;
    }

    public CredentialRegistration getCredentialRegistration () {


        CredentialRegistration reg = CredentialRegistration.builder()
                .userIdentity(getUserIdentity())
                .credentialNickname(Optional.of(nickname))
                .registrationTime(registerTime)
                .credential(getRegisteredCredential())
                .signatureCount(signatureCount)
                .attestationMetadata(Optional.empty())
                .build();
        return reg;
    }

}
