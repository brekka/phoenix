package org.brekka.phoenix.services.impl;

import java.security.MessageDigest;
import java.security.SecureRandom;

import org.brekka.phoenix.config.CryptoFactory;
import org.brekka.phoenix.config.CryptoFactory.SCryptKeyDerivation;
import org.brekka.phoenix.config.CryptoFactory.StandardKeyDerivation;

class CryptoProfileImpl implements org.brekka.phoenix.api.CryptoProfile {

    private final CryptoFactory cryptoFactory;
    
    public CryptoProfileImpl(CryptoFactory cryptoFactory) {
        this.cryptoFactory = cryptoFactory;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.CryptoProfile#getNumber()
     */
    @Override
    public int getNumber() {
        return cryptoFactory.getProfileId();
    }
    
    public MessageDigest getDigestInstance() {
        return cryptoFactory.getDigestInstance();
    }
    
    public SecureRandom getSecureRandom() {
        return cryptoFactory.getSecureRandom();
    }

    public CryptoFactory.Asymmetric getAsymmetric() {
        return cryptoFactory.getAsymmetric();
    }
    
    public SCryptKeyDerivation getSCryptKeyDerivation() {
        return cryptoFactory.getSCryptKeyDerivation();
    }
    
    public StandardKeyDerivation getStandardKeyDerivation() {
        return cryptoFactory.getStandardKeyDerivation();
    }

    public CryptoFactory.Symmetric getSymmetric() {
        return cryptoFactory.getSymmetric();
    }

}
