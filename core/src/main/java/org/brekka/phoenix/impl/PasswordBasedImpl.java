package org.brekka.phoenix.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import org.brekka.phoenix.CryptoFactory;
import org.brekka.phoenix.PhoenixErrorCode;
import org.brekka.phoenix.PhoenixException;
import org.brekka.xml.phoenix.v1.model.PasswordBasedProfileType;

class PasswordBasedImpl implements CryptoFactory.PasswordBased {
    
    private final SecretKeyFactory secretKeyFactory;
    
    private final int saltLength;
    
    private final int iterationFactor;
    
    private final String algorithm;
    
    
    public PasswordBasedImpl(PasswordBasedProfileType profile) {
        this(
            profile.getCipher().getAlgorithm().getStringValue(),
            profile.getSecretKeyFactory().getAlgorithm().getStringValue(),
            profile.getSaltLength(),
            profile.getIterationFactor()
        );
    }
    
    public PasswordBasedImpl(String cipherAlgorithm, String secretKeyAlgorithm, int saltLength, int iterationFactor) {
        try {
            this.secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "Failed to prepare key factory with algorithm '%s'", secretKeyAlgorithm);
        }
        this.saltLength = saltLength;
        this.iterationFactor = iterationFactor;
        this.algorithm = cipherAlgorithm;
    }

    @Override
    public SecretKeyFactory getSecretKeyFactory() {
        return secretKeyFactory;
    }

    @Override
    public int getSaltLength() {
        return saltLength;
    }

    @Override
    public int getIterationFactor() {
        return iterationFactor;
    }

    @Override
    public Cipher getInstance() {
        try {
            return Cipher.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "Failed to prepare key factory/cipher with algorithm '%s'", algorithm);
        }
    }

}
