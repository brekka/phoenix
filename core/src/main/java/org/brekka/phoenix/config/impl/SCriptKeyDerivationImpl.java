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

package org.brekka.phoenix.config.impl;

import org.brekka.phoenix.config.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.KeyDerivationProfileType.SCrypt;

/**
 * TODO Description of SCriptKeyDerivationImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class SCriptKeyDerivationImpl implements CryptoFactory.SCryptKeyDerivation {

    private final int saltLength;
    private final int iterationFactor;
    private final int memoryFactor;
    private final int parallelisation;
    private final int keyLength;
    
    
    /**
     * @param saltLength
     * @param iterationFactor
     * @param memoryFactor
     * @param parallelisation
     * @param keyLength
     */
    public SCriptKeyDerivationImpl(int saltLength, int iterationFactor, int memoryFactor, int parallelisation,
            int keyLength) {
        this.saltLength = saltLength;
        this.iterationFactor = iterationFactor;
        this.memoryFactor = memoryFactor;
        this.parallelisation = parallelisation;
        this.keyLength = keyLength;
    }

    /**
     * @param sCrypt
     */
    public SCriptKeyDerivationImpl(SCrypt sCrypt) {
        this(
            sCrypt.getSaltLength(),
            sCrypt.getIterations(),
            sCrypt.getMemoryFactor(),
            sCrypt.getParallelisationFactor(),
            sCrypt.getKeyLength()
        );
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.CryptoFactory.SCryptKeyDerivation#getSaltLength()
     */
    @Override
    public int getSaltLength() {
        return saltLength;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.CryptoFactory.SCryptKeyDerivation#getIterationFactor()
     */
    @Override
    public int getIterationFactor() {
        return iterationFactor;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.CryptoFactory.SCryptKeyDerivation#getMemoryFactor()
     */
    @Override
    public int getMemoryFactor() {
        return memoryFactor;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.CryptoFactory.SCryptKeyDerivation#getParallelisation()
     */
    @Override
    public int getParallelisation() {
        return parallelisation;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.config.CryptoFactory.SCryptKeyDerivation#getKeyLength()
     */
    @Override
    public int getKeyLength() {
        return keyLength;
    }
}
