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

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.services.CryptoProfileService;
import org.brekka.phoenix.config.CryptoFactoryRegistry;

/**
 * TODO Description of CryptoProfileServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class CryptoProfileServiceImpl implements CryptoProfileService {
    
    private final CryptoFactoryRegistry cryptoFactoryRegistry;

    
    
    /**
     * @param cryptoFactoryRegistry
     */
    public CryptoProfileServiceImpl(CryptoFactoryRegistry cryptoFactoryRegistry) {
        this.cryptoFactoryRegistry = cryptoFactoryRegistry;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.CryptoProfileService#retrieveProfile(int)
     */
    @Override
    public CryptoProfile retrieveProfile(int profileNumber) {
        if (profileNumber == 0) {
            return retrieveDefault();
        }
        return new CryptoProfileImpl(cryptoFactoryRegistry.getFactory(profileNumber));
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.CryptoProfileService#retrieveDefault()
     */
    @Override
    public CryptoProfile retrieveDefault() {
        return new CryptoProfileImpl(cryptoFactoryRegistry.getDefault());
    }

}
