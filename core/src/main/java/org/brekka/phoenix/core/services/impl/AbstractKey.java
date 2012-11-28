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

import org.brekka.phoenix.api.Key;


/**
 * TODO Description of AbstractKey
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
abstract class AbstractKey<K extends java.security.Key> extends AbstractCryptoSpec implements Key {
    
    private final K realKey;
    
    /**
     * @param cryptoProfile
     */
    public AbstractKey(CryptoProfileImpl cryptoProfile, K key) {
        super(cryptoProfile);
        this.realKey = key;
    }


    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.Key#getEncoded()
     */
    @Override
    public byte[] getEncoded() {
        return realKey.getEncoded();
    }
    
    /**
     * @return the realKey
     */
    public K getRealKey() {
        return realKey;
    }
}
