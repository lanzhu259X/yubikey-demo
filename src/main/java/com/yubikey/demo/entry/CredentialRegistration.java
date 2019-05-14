package com.yubikey.demo.entry;

import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.UserIdentity;
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;
import java.util.Date;
import java.util.Optional;

@Builder
@Value
public class CredentialRegistration implements Serializable {

    private static final long serialVersionUID = 388386905766037849L;

    private long signatureCount;

    private UserIdentity userIdentity;

    private Optional<String> credentialNickname;

    private Date registrationTime;

    private RegisteredCredential credential;

    private Optional<Attestation> attestationMetadata;



}
