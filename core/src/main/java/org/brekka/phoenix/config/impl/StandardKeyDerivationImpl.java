package org.brekka.phoenix.config.impl;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKeyFactory;

import org.brekka.phoenix.PhoenixErrorCode;
import org.brekka.phoenix.PhoenixException;
import org.brekka.phoenix.config.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.KeyDerivationProfileType;

class StandardKeyDerivationImpl implements CryptoFactory.StandardKeyDerivation {
    
    private final SecretKeyFactory secretKeyFactory;
    
    private final int saltLength;
    
    private final int iterationFactor;
    
    public StandardKeyDerivationImpl(KeyDerivationProfileType.Standard profile) {
        this(
            profile.getSecretKeyFactory().getAlgorithm().getStringValue(),
            profile.getSaltLength(),
            profile.getIterations()
        );
    }
    
    public StandardKeyDerivationImpl(String secretKeyAlgorithm, int saltLength, int iterationFactor) {
        try {
            this.secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "Failed to prepare key factory with algorithm '%s'", secretKeyAlgorithm);
        }
        this.saltLength = saltLength;
        this.iterationFactor = iterationFactor;
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
    public int getIterations() {
        return iterationFactor;
    }
}
