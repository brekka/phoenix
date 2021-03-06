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

import java.io.InputStream;
import java.io.OutputStream;

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.CryptoResult;
import org.brekka.phoenix.api.DerivedKey;
import org.brekka.phoenix.api.SecretKey;
import org.brekka.phoenix.api.StreamCryptor;
import org.brekka.phoenix.api.SymmetricCryptoSpec;

/**
 * For encrypting large amounts of information with a key that then needs to be protected using a password or asymmetric
 * key.
 * 
 * @author Andrew Taylor (andrew@brekka.org)
 */
public interface SymmetricCryptoService {

    SecretKey createSecretKey(CryptoProfile cryptoProfile);

    SecretKey toSecretKey(byte[] encodedKeyBytes, CryptoProfile cryptoProfile);

    SymmetricCryptoSpec toSymmetricCryptoSpec(DerivedKey derivedKey);

    CryptoResult<SymmetricCryptoSpec> encrypt(byte[] data, SecretKey secretKey);

    CryptoResult<SymmetricCryptoSpec> encrypt(byte[] data, SymmetricCryptoSpec cryptoSpec);

    byte[] decrypt(byte[] data, SymmetricCryptoSpec symmetricSpec);

    StreamCryptor<OutputStream, SymmetricCryptoSpec> encryptor(SecretKey secretKey);

    StreamCryptor<InputStream, SymmetricCryptoSpec> decryptor(SymmetricCryptoSpec symmetricSpec);
}
