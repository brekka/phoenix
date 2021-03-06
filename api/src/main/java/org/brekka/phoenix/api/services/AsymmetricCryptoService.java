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

package org.brekka.phoenix.api.services;

import org.brekka.phoenix.api.AsymmetricKey;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.KeyPair;
import org.brekka.phoenix.api.PrivateKey;
import org.brekka.phoenix.api.PublicKey;
import org.w3c.dom.Document;

/**
 * Encrypt a small piece of data with one (public) key so that it can only be decrypted by the corresponding (private)
 * key.
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public interface AsymmetricCryptoService {

    KeyPair createKeyPair(CryptoProfile cryptoProfile);

    PublicKey toPublicKey(byte[] encodedPublicKeyBytes, CryptoProfile cryptoProfile);

    PrivateKey toPrivateKey(byte[] encodedPrivateKeyBytes, CryptoProfile cryptoProfile);

    <K extends AsymmetricKey> CryptoResult<K> encrypt(byte[] data, K asymmetricKey);

    <K extends AsymmetricKey> byte[] decrypt(byte[] cipherText, K asymmetricKey);

    /**
     * Sign an XML document using the specified key pair.
     *
     * @param document
     * @param keyPair
     * @param cryptoProfile determines which algorithms will be used
     * @return
     */
    Document sign(final Document document, KeyPair keyPair);
}
