package com.yubikey.demo.entry;

import lombok.Data;

import java.util.Objects;

@Data
public class U2FEntry {

    private String username;

    private String keyHandle;

    private String publicKey;

    private String attestationCert;

    private long counter;

    private boolean compromised;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        U2FEntry entry = (U2FEntry) o;
        return Objects.equals(username, entry.username) &&
                Objects.equals(keyHandle, entry.keyHandle);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, keyHandle);
    }
}
