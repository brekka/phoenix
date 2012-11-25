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

import org.brekka.phoenix.api.CryptoSpec;
import org.brekka.phoenix.api.StreamCryptor;

/**
 * TODO Description of AbstractStreamCryptor
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public abstract class AbstractStreamCryptor<Stream, T extends CryptoSpec> implements StreamCryptor<Stream, T> {

    private final T spec;
    
    /**
     * @param spec
     * @param stream
     */
    public AbstractStreamCryptor(T spec) {
        this.spec = spec;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.StreamCryptor#getSpec()
     */
    @Override
    public T getSpec() {
        return spec;
    }
    
}
