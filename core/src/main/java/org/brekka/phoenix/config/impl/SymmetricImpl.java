package org.brekka.phoenix.config.impl;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.brekka.phoenix.PhoenixErrorCode;
import org.brekka.phoenix.PhoenixException;
import org.brekka.phoenix.config.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.SymmetricProfileType;

class SymmetricImpl implements CryptoFactory.Symmetric {

    private final KeyGenerator keyGenerator;
    
    private final int ivLength;
    
    private final String algorithm;
    
    public SymmetricImpl(SymmetricProfileType profile) {
        this(
            profile.getCipher().getAlgorithm().getStringValue(),
            profile.getKeyGenerator().getAlgorithm().getStringValue(),
            profile.getKeyGenerator().getKeyLength(),
            profile.getIVLength()
        );
    }
    
    public SymmetricImpl(String cipherAlgorithm, String keyAlgorithm, int keyLength, int ivLength) {
        try {
            this.keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
            this.keyGenerator.init(keyLength);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP101, e, 
                    "Problem with the symmetric key generator algorithm '%s', key length %d", 
                    keyAlgorithm, keyLength);
        }
        this.ivLength = ivLength;
        this.algorithm = cipherAlgorithm;
    }

    @Override
    public KeyGenerator getKeyGenerator() {
        return keyGenerator;
    }

    @Override
    public Cipher getInstance() {
        try {
            return Cipher.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP101, e, 
                    "Problem with the symmetric encryption algorithm '%s'", 
                    algorithm);
        }
    }

    @Override
    public int getIvLength() {
        return ivLength;
    }

}
