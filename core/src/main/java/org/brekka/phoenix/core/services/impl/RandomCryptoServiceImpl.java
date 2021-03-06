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

import java.security.SecureRandom;

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.services.RandomCryptoService;

/**
 * TODO Description of RandomCryptoServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class RandomCryptoServiceImpl extends CryptoServiceSupport implements RandomCryptoService {

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.RandomCryptoService#getSecureRandom(org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public SecureRandom getSecureRandom(CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        return profile.getFactory().getSecureRandom();
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.RandomCryptoService#getSecureRandom()
     */
    @Override
    public SecureRandom getSecureRandom() {
        return getSecureRandom(CryptoProfile.DEFAULT);
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.RandomCryptoService#generateRandomBytes(int)
     */
    @Override
    public byte[] generateBytes(int length) {
        byte[] data = new byte[length];
        getSecureRandom().nextBytes(data);
        return data;
    }
}
