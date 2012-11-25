/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.brekka.phoenix.services.impl;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.brekka.phoenix.PhoenixErrorCode;
import org.brekka.phoenix.PhoenixException;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.StreamCryptor;
import org.brekka.phoenix.api.SymmetricCryptoSpec;
import org.brekka.phoenix.api.services.SymmetricCryptoService;
import org.brekka.phoenix.config.CryptoFactory;

/**
 * TODO Description of SymmetricCryptoServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class SymmetricCryptoServiceImpl extends CryptoServiceSupport implements SymmetricCryptoService {

    
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#createSecretKey(org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public SecretKey createSecretKey(CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        CryptoFactory.Symmetric symmetric = profile.getSymmetric();
        KeyGenerator keyGenerator = symmetric.getKeyGenerator();
        javax.crypto.SecretKey generatedKey = keyGenerator.generateKey();
        return new SecretKeyImpl(profile, generatedKey);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#toSecretKey(byte[], org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public SecretKey toSecretKey(byte[] encodedKeyBytes, CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        CryptoFactory.Symmetric symmetric = profile.getSymmetric();
        javax.crypto.SecretKey secretKey = new SecretKeySpec(encodedKeyBytes, symmetric.getKeyGenerator().getAlgorithm());
        return new SecretKeyImpl(profile, secretKey);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#encrypt(byte[], org.brekka.phoenix.api.SecretKey)
     */
    @Override
    public CryptoResult<SymmetricCryptoSpec> encrypt(byte[] data, SecretKey secretKey) {
        SymmetricCryptoSpecImpl spec = prepareSpec(secretKey);
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, spec);
        
        byte[] cipherData;
        try {
            cipherData = cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP105, e, 
                    "Failed to symmetric encrypt object");
        }
        return new CryptoResultImpl<SymmetricCryptoSpec>(spec, cipherData);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#decrypt(byte[], org.brekka.phoenix.api.SymmetricCryptoSpec)
     */
    @Override
    public byte[] decrypt(byte[] cipherText, SymmetricCryptoSpec symmetricSpec) {
        SymmetricCryptoSpecImpl spec = narrowSpec(symmetricSpec);
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, spec);
        byte[] data;
        try {
            data = cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP106, e, 
                    "Failed to decrypt %d bytes of data", cipherText.length);
        }
        return data;
    }


    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#encryptor(org.brekka.phoenix.api.SecretKey)
     */
    @Override
    public StreamCryptor<OutputStream, SymmetricCryptoSpec> encryptor(SecretKey secretKey) {
        SymmetricCryptoSpecImpl spec = prepareSpec(secretKey);
        final Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, spec);
        return new AbstractStreamCryptor<OutputStream, SymmetricCryptoSpec>(spec) {
            /* (non-Javadoc)
             * @see org.brekka.phoenix.api.StreamCryptor#getStream(java.lang.Object)
             */
            @Override
            public OutputStream getStream(OutputStream stream) {
                return new CipherOutputStream(stream, cipher);
            }
        };
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#decryptor(org.brekka.phoenix.api.SymmetricCryptoSpec)
     */
    @Override
    public StreamCryptor<InputStream, SymmetricCryptoSpec> decryptor(SymmetricCryptoSpec symmetricSpec) {
        SymmetricCryptoSpecImpl spec = narrowSpec(symmetricSpec);
        final Cipher cipher = getCipher(Cipher.DECRYPT_MODE, spec);
        return new AbstractStreamCryptor<InputStream, SymmetricCryptoSpec>(spec) {
            /* (non-Javadoc)
             * @see org.brekka.phoenix.api.StreamCryptor#getStream(java.lang.Object)
             */
            @Override
            public InputStream getStream(InputStream stream) {
                return new CipherInputStream(stream, cipher);
            }
        };
    }
    
    protected IvParameterSpec generateInitializationVector(CryptoProfileImpl profile) {
        byte[] ivBytes = new byte[profile.getSymmetric().getIvLength()];
        profile.getSecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        return iv;
    }


    /**
     * @param secretKey
     * @return
     */
    protected SymmetricCryptoSpecImpl prepareSpec(SecretKey secretKey) {
        SecretKeyImpl secretKeyImpl = narrowSecretKey(secretKey);
        CryptoProfileImpl profile = narrowProfile(secretKeyImpl.getProfile());
        IvParameterSpec initializationVector = generateInitializationVector(profile);
        SymmetricCryptoSpecImpl spec = new SymmetricCryptoSpecImpl(profile, secretKeyImpl, initializationVector);
        return spec;
    }
    
    protected Cipher getCipher(int mode, SymmetricCryptoSpecImpl spec) {
        java.security.Key key = spec.getSecretKey().getRealKey();
        AlgorithmParameterSpec parameter = spec.getIvParameterSpec();
        CryptoFactory.Symmetric symmetricProfile = spec.getCryptoProfileImpl().getSymmetric();
        Cipher cipher = symmetricProfile.getInstance();
        try {
            cipher.init(mode, key, parameter);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP102, e, 
                    "Problem initializing symmetric cipher");
        }
        return cipher;
    }

    /**
     * @param key
     * @param class1
     * @return
     */
    protected SecretKeyImpl narrowSecretKey(SecretKey key) {
        if (key instanceof SecretKeyImpl) {
            return (SecretKeyImpl) key;
        }
        return (SecretKeyImpl) toSecretKey(key.getEncoded(), key.getProfile()) ;
    }


    /**
     * @param symmetricSpec
     * @return
     */
    protected SymmetricCryptoSpecImpl narrowSpec(SymmetricCryptoSpec symmetricSpec) {
        if (symmetricSpec instanceof SymmetricCryptoSpecImpl) {
            return (SymmetricCryptoSpecImpl) symmetricSpec;
        }
        IvParameterSpec initializationVector = new IvParameterSpec(symmetricSpec.getIV());
        SecretKeyImpl secretKeyImpl = narrowSecretKey(symmetricSpec.getKey());
        CryptoProfileImpl profile = narrowProfile(symmetricSpec.getProfile());
        return new SymmetricCryptoSpecImpl(profile, secretKeyImpl, initializationVector);
    }
}
