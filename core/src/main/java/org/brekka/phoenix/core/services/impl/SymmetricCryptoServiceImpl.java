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

package org.brekka.phoenix.core.services.impl;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.DerivedKey;
import org.brekka.phoenix.api.DigestResult;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.StreamCryptor;
import org.brekka.phoenix.api.SymmetricCryptoSpec;
import org.brekka.phoenix.api.services.DigestCryptoService;
import org.brekka.phoenix.api.services.SymmetricCryptoService;
import org.brekka.phoenix.core.PhoenixErrorCode;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.services.CryptoFactory;

/**
 * TODO Description of SymmetricCryptoServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class SymmetricCryptoServiceImpl extends CryptoServiceSupport implements SymmetricCryptoService {

    private DigestCryptoService digestCryptoService;

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#createSecretKey(org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public SecretKey createSecretKey(final CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        CryptoFactory.Symmetric symmetric = profile.getFactory().getSymmetric();
        KeyGenerator keyGenerator = symmetric.getKeyGenerator();
        javax.crypto.SecretKey generatedKey = keyGenerator.generateKey();
        return new SecretKeyImpl(profile, generatedKey);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#toSecretKey(byte[], org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public SecretKey toSecretKey(final byte[] encodedKeyBytes, final CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        CryptoFactory.Symmetric symmetric = profile.getFactory().getSymmetric();
        javax.crypto.SecretKey secretKey = new SecretKeySpec(encodedKeyBytes, symmetric.getKeyGenerator().getAlgorithm());
        return new SecretKeyImpl(profile, secretKey);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#toSymmetricCryptoSpec(org.brekka.phoenix.api.DerivedKey)
     */
    @Override
    public SymmetricCryptoSpec toSymmetricCryptoSpec(final DerivedKey derivedKey) {
        CryptoProfileImpl profile = narrowProfile(derivedKey.getCryptoProfile());
        byte[] salt = derivedKey.getSalt();
        byte[] dKey = derivedKey.getDerivedKey();
        SecretKeyImpl secretKey = (SecretKeyImpl) toSecretKey(dKey, profile);
        IvParameterSpec iv = new IvParameterSpec(saltToIv(salt, profile));
        return new SymmetricCryptoSpecImpl(profile, secretKey, iv);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#encrypt(byte[], org.brekka.phoenix.api.SymmetricCryptoSpec)
     */
    @Override
    public CryptoResult<SymmetricCryptoSpec> encrypt(final byte[] data, final SymmetricCryptoSpec symmetricSpec) {
        SymmetricCryptoSpecImpl spec = narrowSpec(symmetricSpec);
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, spec);

        byte[] cipherData;
        try {
            cipherData = cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP105, e,
                    "Failed to symmetric encrypt object");
        }
        return new CryptoResultImpl<>(spec, cipherData);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#encrypt(byte[], org.brekka.phoenix.api.SecretKey)
     */
    @Override
    public CryptoResult<SymmetricCryptoSpec> encrypt(final byte[] data, final SecretKey secretKey) {
        SymmetricCryptoSpecImpl spec = prepareSpec(secretKey);
        return encrypt(data, spec);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#decrypt(byte[], org.brekka.phoenix.api.SymmetricCryptoSpec)
     */
    @Override
    public byte[] decrypt(final byte[] cipherText, final SymmetricCryptoSpec symmetricSpec) {
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
    public StreamCryptor<OutputStream, SymmetricCryptoSpec> encryptor(final SecretKey secretKey) {
        SymmetricCryptoSpecImpl spec = prepareSpec(secretKey);
        final Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, spec);
        return new AbstractStreamCryptor<OutputStream, SymmetricCryptoSpec>(spec) {
            /* (non-Javadoc)
             * @see org.brekka.phoenix.api.StreamCryptor#getStream(java.lang.Object)
             */
            @Override
            public OutputStream getStream(final OutputStream stream) {
                return new CipherOutputStream(stream, cipher);
            }
        };
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.SymmetricCryptoService#decryptor(org.brekka.phoenix.api.SymmetricCryptoSpec)
     */
    @Override
    public StreamCryptor<InputStream, SymmetricCryptoSpec> decryptor(final SymmetricCryptoSpec symmetricSpec) {
        SymmetricCryptoSpecImpl spec = narrowSpec(symmetricSpec);
        final Cipher cipher = getCipher(Cipher.DECRYPT_MODE, spec);
        return new AbstractStreamCryptor<InputStream, SymmetricCryptoSpec>(spec) {
            /* (non-Javadoc)
             * @see org.brekka.phoenix.api.StreamCryptor#getStream(java.lang.Object)
             */
            @Override
            public InputStream getStream(final InputStream stream) {
                return new CipherInputStream(stream, cipher);
            }
        };
    }

    /**
     * @param salt
     * @param profile
     * @return
     */
    protected byte[] saltToIv(final byte[] salt, final CryptoProfileImpl profile) {
        DigestResult digestResult = digestCryptoService.digest(salt, profile);
        byte[] digest = digestResult.getDigest();
        int requiredIvLength = profile.getFactory().getSymmetric().getIvLength();
        // Reduce the digest down to the IV length
        if (requiredIvLength > digest.length) {
            throw new PhoenixException(PhoenixErrorCode.CP104,
                    "Digest algrithm did not produce enough bytes (%d) to satisfy IV length (%d)",
                    digest.length, requiredIvLength);
        }
        return Arrays.copyOfRange(digest, 0, requiredIvLength);
    }

    protected IvParameterSpec generateInitializationVector(final CryptoProfileImpl profile) {
        CryptoFactory factory = profile.getFactory();
        byte[] ivBytes = new byte[factory.getSymmetric().getIvLength()];
        factory.getSecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        return iv;
    }


    /**
     * @param secretKey
     * @return
     */
    protected SymmetricCryptoSpecImpl prepareSpec(final SecretKey secretKey) {
        SecretKeyImpl secretKeyImpl = narrowSecretKey(secretKey);
        CryptoProfileImpl profile = narrowProfile(secretKeyImpl.getCryptoProfile());
        IvParameterSpec initializationVector = generateInitializationVector(profile);
        SymmetricCryptoSpecImpl spec = new SymmetricCryptoSpecImpl(profile, secretKeyImpl, initializationVector);
        return spec;
    }

    protected Cipher getCipher(final int mode, final SymmetricCryptoSpecImpl spec) {
        java.security.Key key = spec.getSecretKeyImpl().getRealKey();
        AlgorithmParameterSpec parameter = spec.getIvParameterSpec();
        CryptoFactory.Symmetric symmetricProfile = spec.getCryptoProfileImpl().getFactory().getSymmetric();
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
    protected SecretKeyImpl narrowSecretKey(final SecretKey key) {
        if (key instanceof SecretKeyImpl) {
            return (SecretKeyImpl) key;
        }
        return (SecretKeyImpl) toSecretKey(key.getEncoded(), key.getCryptoProfile()) ;
    }


    /**
     * @param symmetricSpec
     * @return
     */
    protected SymmetricCryptoSpecImpl narrowSpec(final SymmetricCryptoSpec symmetricSpec) {
        if (symmetricSpec instanceof SymmetricCryptoSpecImpl) {
            return (SymmetricCryptoSpecImpl) symmetricSpec;
        }
        IvParameterSpec initializationVector = new IvParameterSpec(symmetricSpec.getIv());
        SecretKeyImpl secretKeyImpl = narrowSecretKey(symmetricSpec.getSecretKey());
        CryptoProfileImpl profile = narrowProfile(symmetricSpec.getCryptoProfile());
        return new SymmetricCryptoSpecImpl(profile, secretKeyImpl, initializationVector);
    }

    /**
     * @param digestCryptoService the digestCryptoService to set
     */
    public void setDigestCryptoService(final DigestCryptoService digestCryptoService) {
        this.digestCryptoService = digestCryptoService;
    }
}
