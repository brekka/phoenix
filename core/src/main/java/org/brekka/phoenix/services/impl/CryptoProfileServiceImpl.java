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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.services.CryptoProfileService;
import org.brekka.phoenix.config.impl.CryptoFactoryImpl;
import org.brekka.xml.phoenix.v2.model.CryptoProfileDocument;
import org.brekka.xml.phoenix.v2.model.CryptoProfileRegistryDocument.CryptoProfileRegistry;

/**
 * TODO Description of CryptoProfileServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class CryptoProfileServiceImpl implements CryptoProfileService {
    
    private final Map<Integer, CryptoProfileImpl> profiles = new HashMap<>();
    
    private final int defaultProfileNumber;
    
    /**
     * @param cryptoFactoryRegistry
     */
    public CryptoProfileServiceImpl(CryptoProfileRegistry cryptoProfileRegistry) {
        List<CryptoProfileDocument.CryptoProfile> cryptoProfileList = cryptoProfileRegistry.getCryptoProfileList();
        for (CryptoProfileDocument.CryptoProfile cryptoProfile : cryptoProfileList) {
            CryptoFactoryImpl cryptoFactoryImpl = new CryptoFactoryImpl(cryptoProfile);
            CryptoProfileImpl profile = new CryptoProfileImpl(cryptoFactoryImpl);
            this.profiles.put(profile.getNumber(), profile);
        }
        this.defaultProfileNumber = cryptoProfileRegistry.getDefaultProfileID();
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.CryptoProfileService#retrieveProfile(int)
     */
    @Override
    public CryptoProfile retrieveProfile(int profileNumber) {
        if (profileNumber == CryptoProfile.DEFAULT.getNumber()) {
            return retrieveDefault();
        }
        return this.profiles.get(profileNumber);
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.CryptoProfileService#retrieveDefault()
     */
    @Override
    public CryptoProfile retrieveDefault() {
        return profiles.get(defaultProfileNumber);
    }

}
