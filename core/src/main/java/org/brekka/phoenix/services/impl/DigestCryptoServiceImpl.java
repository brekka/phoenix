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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.DigestResult;
import org.brekka.phoenix.api.StreamCryptor;
import org.brekka.phoenix.api.services.DigestCryptoService;

/**
 * TODO Description of DigestCryptoServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class DigestCryptoServiceImpl extends CryptoServiceSupport implements DigestCryptoService {

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.DigestCryptoService#digest(byte[], org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public DigestResult digest(byte[] data, CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        MessageDigest digestInstance = profile.getDigestInstance();
        byte[] digest = digestInstance.digest(data);
        return new DigestResultImpl(profile, digest);
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.DigestCryptoService#getDigestLength(org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public int getDigestLength(CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        // TODO Avoid creating instance to find length (every time)
        MessageDigest digestInstance = profile.getDigestInstance();
        return digestInstance.getDigestLength();
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.DigestCryptoService#digester(org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public StreamCryptor<InputStream, DigestResult> inputDigester(CryptoProfile cryptoProfile) {
        final CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        final MessageDigest digestInstance = profile.getDigestInstance();
        return new StreamCryptor<InputStream, DigestResult>() {
            
            @Override
            public InputStream getStream(InputStream stream) {
                return new DigestInputStream(stream, digestInstance);
            }
            
            @Override
            public DigestResult getSpec() {
                return new DigestResultImpl(profile, digestInstance.digest());
            }
        };
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.DigestCryptoService#outputDigester(org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public StreamCryptor<OutputStream, DigestResult> outputDigester(CryptoProfile cryptoProfile) {
        final CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        final MessageDigest digestInstance = profile.getDigestInstance();
        return new StreamCryptor<OutputStream, DigestResult>() {
            
            @Override
            public OutputStream getStream(OutputStream stream) {
                return new DigestOutputStream(stream, digestInstance);
            }
            
            @Override
            public DigestResult getSpec() {
                return new DigestResultImpl(profile, digestInstance.digest());
            }
        };
    }
}
