package org.brekka.phoenix.impl;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

import org.brekka.phoenix.PhoenixErrorCode;
import org.brekka.phoenix.PhoenixException;
import org.brekka.phoenix.CryptoFactory;
import org.brekka.xml.phoenix.v1.model.AsymmetricProfileType;

class AsymmetricImpl implements CryptoFactory.Asymmetric {

    private final KeyFactory keyFactory;
    
    private final KeyPairGenerator keyPairGenerator;
    
    private final String algorithm;
    
    public AsymmetricImpl(AsymmetricProfileType profile) {
        this(
            profile.getCipher().getAlgorithm().getStringValue(),
            profile.getKeyFactory().getAlgorithm().getStringValue(),
            profile.getKeyPairGenerator().getAlgorithm().getStringValue(),
            profile.getKeyPairGenerator().getKeyLength()
        );
    }
    
    public AsymmetricImpl(String cipherAlgorithm, String keyFactoryAlgorithm, String keyPairGeneratorAlgorithm, int keyPairLength) {
        this.algorithm = cipherAlgorithm;
        try {
            this.keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm);
            this.keyPairGenerator = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
            this.keyPairGenerator.initialize(keyPairLength);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP205, e, 
                    "Key algorithm '%s' not found", algorithm);
        }
    }

    @Override
    public KeyFactory getKeyFactory() {
        return keyFactory;
    }
    
    @Override
    public KeyPair generateKeyPair() {
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public Cipher getInstance() {
        try {
            return Cipher.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP205, e, 
                    "Asymmetric key algorithm '%s' not found", algorithm);
        }
    }

}