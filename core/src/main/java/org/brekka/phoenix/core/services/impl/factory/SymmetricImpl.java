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
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.brekka.phoenix.core.PhoenixErrorCode;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.services.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.SymmetricProfileType;

class SymmetricImpl implements CryptoFactory.Symmetric {

    private final KeyGenerator keyGenerator;
    
    private final int ivLength;
    
    private final String algorithm;
    
    public SymmetricImpl(SecureRandom secureRandom, SymmetricProfileType profile) {
        this(secureRandom,
            profile.getCipher().getAlgorithm().getStringValue(),
            profile.getKeyGenerator().getAlgorithm().getStringValue(),
            profile.getKeyGenerator().getKeyLength(),
            profile.getIVLength()
        );
    }
    
    public SymmetricImpl(SecureRandom secureRandom, String cipherAlgorithm, String keyAlgorithm, int keyLength, int ivLength) {
        try {
            this.keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
            this.keyGenerator.init(keyLength, secureRandom);
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
