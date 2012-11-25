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

import org.brekka.phoenix.api.DerivedKey;

/**
 * TODO Description of DerivedKeyImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class DerivedKeyImpl extends AbstractCryptoSpec implements DerivedKey {

    private final Integer iterations;
    private final byte[] salt;
    private final byte[] derivedKey;
    
    /**
     * @param cryptoProfile
     * @param iterations
     * @param memoryFactor
     * @param parallelisationFactor
     * @param salt
     * @param derivedKey
     */
    public DerivedKeyImpl(CryptoProfileImpl cryptoProfile, Integer iterations, byte[] salt, byte[] derivedKey) {
        super(cryptoProfile);
        this.iterations = iterations;
        this.salt = salt;
        this.derivedKey = derivedKey;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.DerivedKey#getIterations()
     */
    @Override
    public Integer getIterations() {
        return iterations;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.DerivedKey#getSalt()
     */
    @Override
    public byte[] getSalt() {
        return salt;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.DerivedKey#getDerivedKey()
     */
    @Override
    public byte[] getDerivedKey() {
        return derivedKey;
    }

}
