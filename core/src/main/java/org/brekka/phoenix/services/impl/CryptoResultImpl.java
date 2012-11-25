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

import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.CryptoSpec;

/**
 * TODO Description of CryptoResultImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
class CryptoResultImpl<T extends CryptoSpec> implements CryptoResult<T> {

    private final T spec;
    
    private final byte[] cipherText;
    
    
    
    /**
     * @param spec
     * @param cipherText
     */
    public CryptoResultImpl(T spec, byte[] cipherText) {
        this.spec = spec;
        this.cipherText = cipherText;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.CryptoResult#getSpec()
     */
    @Override
    public T getSpec() {
        return spec;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.CryptoResult#getCipherText()
     */
    @Override
    public byte[] getCipherText() {
        return cipherText;
    }

    
}
