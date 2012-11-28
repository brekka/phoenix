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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.brekka.phoenix.api.AsymmetricCryptoSpec;
import org.brekka.phoenix.api.AsymmetricKey;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.KeyPair;
import org.brekka.phoenix.api.PrivateKey;
import org.brekka.phoenix.api.PublicKey;
import org.brekka.phoenix.api.services.AsymmetricCryptoService;
import org.brekka.phoenix.core.PhoenixErrorCode;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.services.CryptoFactory;

/**
 * TODO Description of AsymmetricCryptoServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class AsymmetricCryptoServiceImpl extends CryptoServiceSupport implements AsymmetricCryptoService {

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.AsymmetricCryptoService#createKeyPair(org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public KeyPair createKeyPair(CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        CryptoFactory.Asymmetric asymmetric = profile.getFactory().getAsymmetric();
        java.security.KeyPair keyPair = asymmetric.generateKeyPair();
        return new KeyPairImpl(
                new PublicKeyImpl(profile, keyPair.getPublic()), 
                new PrivateKeyImpl(profile, keyPair.getPrivate()));
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.AsymmetricCryptoService#toPublicKey(byte[], org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public PublicKey toPublicKey(byte[] encodedPublicKeyBytes, CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        CryptoFactory.Asymmetric asymmetric = profile.getFactory().getAsymmetric();
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKeyBytes);
        java.security.PublicKey publicKey;
        try {
            KeyFactory keyFactory = asymmetric.getKeyFactory();
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new PhoenixException(PhoenixErrorCode.CP200, e, 
                    "Failed to extract public key");
        }
        return new PublicKeyImpl(profile, publicKey);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.AsymmetricCryptoService#toPrivateKey(byte[], org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public PrivateKey toPrivateKey(byte[] encodedPrivateKeyBytes, CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        CryptoFactory.Asymmetric asymmetric = profile.getFactory().getAsymmetric();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKeyBytes);
        java.security.PrivateKey privateKey;
        try {
            KeyFactory keyFactory = asymmetric.getKeyFactory();
            privateKey =  keyFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new PhoenixException(PhoenixErrorCode.CP207, e, 
                    "Failed to extract private key");
        }
        return new PrivateKeyImpl(profile, privateKey);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.AsymmetricCryptoService#encrypt(byte[], org.brekka.phoenix.api.AsymmetricKey)
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Override
    public <K extends AsymmetricKey> CryptoResult<K> encrypt(byte[] data,
            K asymmetricKey) {
        AbstractAsymmetricKey<Key> keyImpl = narrowKey(asymmetricKey);
        Cipher cipher = getAsymmetricCipher(Cipher.ENCRYPT_MODE, keyImpl);
        byte[] cipherText;
        try {
            cipherText = cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP212, e,
                    "Failed to encrypt using asynchronous");
        }
        return new CryptoResultImpl(keyImpl, cipherText);
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.AsymmetricCryptoService#decrypt(byte[], org.brekka.phoenix.api.AsymmetricCryptoSpec)
     */
    @Override
    public <K extends AsymmetricKey> byte[] decrypt(byte[] cipherText, K asymmetricKey) {
        AbstractAsymmetricKey<Key> keyImpl = narrowKey(asymmetricKey);
        Cipher cipher = getAsymmetricCipher(Cipher.DECRYPT_MODE, keyImpl);
        byte[] data;
        try {
            data = cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP211, e,
                    "Failed to decrypt using asynchronous");
        }
        return data;
    }
    
    @SuppressWarnings({ "rawtypes", "unchecked" })
    protected AsymmetricCryptoSpecImpl<AbstractAsymmetricKey<Key>> narrowSpec(AsymmetricCryptoSpec<?> spec) {
        CryptoProfileImpl profile = narrowProfile(spec.getCryptoProfile());
        if (spec instanceof AsymmetricCryptoSpecImpl) {
            return (AsymmetricCryptoSpecImpl<AbstractAsymmetricKey<Key>>) spec;
        }
        AbstractAsymmetricKey<?> asymKey = narrowKey(spec.getKey());
        return new AsymmetricCryptoSpecImpl(profile, asymKey);
    }
    
    @SuppressWarnings("unchecked")
    protected AbstractAsymmetricKey<Key> narrowKey(AsymmetricKey key) {
        CryptoProfileImpl profile = narrowProfile(key.getCryptoProfile());
        AbstractAsymmetricKey<?> asymKey;
        if (key instanceof PublicKey) {
            PublicKey publicKey = (PublicKey) key;
            asymKey = (PublicKeyImpl) toPublicKey(publicKey.getEncoded(), profile);
        } else if (key instanceof PrivateKey) {
            PrivateKey privateKey = (PrivateKey) key;
            asymKey = (PrivateKeyImpl) toPrivateKey(privateKey.getEncoded(), profile);
        } else {
            throw new PhoenixException(PhoenixErrorCode.CP203, 
                    "Not an asymmetric key type '%s'", key.getClass().getName());
        }
        return (AbstractAsymmetricKey<Key>) asymKey;
    }
    
    protected Cipher getAsymmetricCipher(int mode, AbstractAsymmetricKey<Key> key) {
        CryptoFactory.Asymmetric asymmetric = key.getCryptoProfileImpl().getFactory().getAsymmetric();
        Cipher cipher = asymmetric.getInstance();
        try {
            Key realKey = key.getRealKey();
            cipher.init(mode, realKey);
        } catch (InvalidKeyException e) {
            throw new PhoenixException(PhoenixErrorCode.CP206, e, 
                    "Problem initializing asymmetric cipher");
        }
        return cipher;
    }

}
