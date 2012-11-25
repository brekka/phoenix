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

import org.brekka.phoenix.PhoenixErrorCode;
import org.brekka.phoenix.PhoenixException;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.Key;
import org.brekka.phoenix.api.services.CryptoProfileService;

/**
 * TODO Description of CryptoServiceSupport
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
class CryptoServiceSupport {

    private CryptoProfileService cryptoProfileService;
    
    
    protected CryptoProfileImpl narrowProfile(CryptoProfile cryptoProfile) {
        if (cryptoProfile instanceof CryptoProfileImpl) {
            return (CryptoProfileImpl) cryptoProfile;
        }
        return (CryptoProfileImpl) cryptoProfileService.retrieveProfile(cryptoProfile.getNumber());
    }
    
    /**
     * @param object
     * @param expected
     * @return
     */
    @SuppressWarnings("unchecked")
    protected <I extends Key, T extends I> T narrow(I object, Class<T> expected) {
        if (!expected.isAssignableFrom(object.getClass())) {
            throw new PhoenixException(PhoenixErrorCode.CP107, 
                    "Expected internal implementation of '%s', found '%s'", 
                    expected.getName(), object.getClass().getName());
        }
        return (T) object;
    }
    
    /**
     * @param cryptoProfileService the cryptoProfileService to set
     */
    public void setCryptoProfileService(CryptoProfileService cryptoProfileService) {
        this.cryptoProfileService = cryptoProfileService;
    }
}
