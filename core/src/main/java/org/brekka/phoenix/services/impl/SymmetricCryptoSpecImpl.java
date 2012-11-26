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


import javax.crypto.spec.IvParameterSpec;

import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.SymmetricCryptoSpec;

/**
 * TODO Description of SymmetricCryptoSpecImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
class SymmetricCryptoSpecImpl extends AbstractCryptoSpec implements SymmetricCryptoSpec {

    private final SecretKeyImpl secretKey;
    
    private final IvParameterSpec ivParameterSpec;
    
    /**
     * @param cryptoProfile
     * @param secretKey
     * @param ivParameterSpec
     */
    public SymmetricCryptoSpecImpl(CryptoProfileImpl cryptoProfile, SecretKeyImpl secretKey, IvParameterSpec ivParameterSpec) {
        super(cryptoProfile);
        this.secretKey = secretKey;
        this.ivParameterSpec = ivParameterSpec;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.SymmetricCryptoSpec#getKey()
     */
    @Override
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.SymmetricCryptoSpec#getIV()
     */
    @Override
    public byte[] getIV() {
        return ivParameterSpec.getIV();
    }
    
    /**
     * @return the secretKey
     */
    public SecretKeyImpl getSecretKeyImpl() {
        return secretKey;
    }
    
    /**
     * @return the ivParameterSpec
     */
    public IvParameterSpec getIvParameterSpec() {
        return ivParameterSpec;
    }

}
