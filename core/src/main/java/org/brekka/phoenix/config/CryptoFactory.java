package org.brekka.phoenix.config;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;

public interface CryptoFactory {

    int getProfileId();
    
    MessageDigest getDigestInstance();
    
    SecureRandom getSecureRandom();
    
    Symmetric getSymmetric();
    
    Asymmetric getAsymmetric();
    
    StandardKeyDerivation getStandardKeyDerivation();
    
    SCryptKeyDerivation getSCryptKeyDerivation();
    
    interface Asymmetric {
        KeyFactory getKeyFactory();
        
        KeyPair generateKeyPair();
        
        Cipher getInstance();
    }
    
    interface StandardKeyDerivation {
        SecretKeyFactory getSecretKeyFactory();
        
        int getSaltLength();
        
        int getIterations();
    }
    
    interface SCryptKeyDerivation {
        int getSaltLength();
        int getIterationFactor();
        int getMemoryFactor();
        int getParallelisation();
        int getKeyLength();
    }
    
    interface Symmetric {
        KeyGenerator getKeyGenerator();
        
        Cipher getInstance();
        
        int getIvLength();
    }
}
