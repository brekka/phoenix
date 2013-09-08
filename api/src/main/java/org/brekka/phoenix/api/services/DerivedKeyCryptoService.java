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

import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.DerivedKey;

/**
 * Normally used for protecting passwords.
 * 
 * Convert a key into another representation from which it hoped it is impossible to extract the original, also ensuring
 * that the resulting representation has a very low chance of collision with the results of other keys.
 * 
 * @author Andrew Taylor (andrew@brekka.org)
 */
public interface DerivedKeyCryptoService {

    DerivedKey apply(byte[] key, byte[] salt, Integer iterations, CryptoProfile cryptoProfile);

    DerivedKey apply(byte[] key, CryptoProfile cryptoProfile);

    boolean check(byte[] key, DerivedKey derivedKey);

}
