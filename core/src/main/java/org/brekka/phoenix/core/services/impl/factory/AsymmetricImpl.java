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

package org.brekka.phoenix.core.services.impl.factory;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.brekka.phoenix.core.PhoenixErrorCode;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.services.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.AsymmetricProfileType;

class AsymmetricImpl implements CryptoFactory.Asymmetric {

    private final KeyFactory keyFactory;
    
    private final KeyPairGenerator keyPairGenerator;
    
    private final String algorithm;
    
    public AsymmetricImpl(SecureRandom secureRandom, AsymmetricProfileType profile) {
        this(secureRandom,
            profile.getCipher().getAlgorithm().getStringValue(),
            profile.getKeyFactory().getAlgorithm().getStringValue(),
            profile.getKeyPairGenerator().getAlgorithm().getStringValue(),
            profile.getKeyPairGenerator().getKeyLength()
        );
    }
    
    public AsymmetricImpl(SecureRandom secureRandom, String cipherAlgorithm, String keyFactoryAlgorithm, String keyPairGeneratorAlgorithm, int keyPairLength) {
        this.algorithm = cipherAlgorithm;
        try {
            this.keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm);
            this.keyPairGenerator = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
            this.keyPairGenerator.initialize(keyPairLength, secureRandom);
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
