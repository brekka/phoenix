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

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoSpec;

/**
 * TODO Description of AbstractCryptoSpec
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
class AbstractCryptoSpec implements CryptoSpec {

    private final CryptoProfileImpl cryptoProfile;
    
    /**
     * @param cryptoProfile
     */
    public AbstractCryptoSpec(CryptoProfileImpl cryptoProfile) {
        this.cryptoProfile = cryptoProfile;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.CryptoSpec#getProfile()
     */
    @Override
    public CryptoProfile getCryptoProfile() {
        return cryptoProfile;
    }

    /**
     * @return the cryptoProfile
     */
    public CryptoProfileImpl getCryptoProfileImpl() {
        return cryptoProfile;
    }
}
