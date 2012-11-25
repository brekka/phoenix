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

import org.brekka.phoenix.api.KeyPair;
import org.brekka.phoenix.api.PrivateKey;
import org.brekka.phoenix.api.PublicKey;

/**
 * TODO Description of KeyPairImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
class KeyPairImpl implements KeyPair {

    private final PublicKey publicKey;
    
    private final PrivateKey privateKey;
    
    /**
     * @param publicKey
     * @param privateKey
     */
    public KeyPairImpl(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.KeyPair#getPublicKey()
     */
    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.KeyPair#getPrivateKey()
     */
    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

}
