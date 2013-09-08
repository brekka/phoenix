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

import javax.crypto.SecretKeyFactory;

import org.brekka.phoenix.core.PhoenixErrorCode;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.services.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.KeyDerivationProfileType;

class StandardKeyDerivationImpl implements CryptoFactory.StandardKeyDerivation {
    
    private final SecretKeyFactory secretKeyFactory;
    
    private final int saltLength;
    
    private final int iterationFactor;
    
    public StandardKeyDerivationImpl(KeyDerivationProfileType.Standard profile) {
        this(
            profile.getSecretKeyFactory().getAlgorithm().getStringValue(),
            profile.getSaltLength(),
            profile.getIterations()
        );
    }
    
    public StandardKeyDerivationImpl(String secretKeyAlgorithm, int saltLength, int iterationFactor) {
        try {
            this.secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "Failed to prepare key factory with algorithm '%s'", secretKeyAlgorithm);
        }
        this.saltLength = saltLength;
        this.iterationFactor = iterationFactor;
    }

    @Override
    public SecretKeyFactory getSecretKeyFactory() {
        return secretKeyFactory;
    }

    @Override
    public int getSaltLength() {
        return saltLength;
    }

    @Override
    public int getIterations() {
        return iterationFactor;
    }
}
