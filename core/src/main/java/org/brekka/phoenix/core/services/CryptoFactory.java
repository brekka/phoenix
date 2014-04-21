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

package org.brekka.phoenix.core.services;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.xml.crypto.dsig.XMLSignatureFactory;

public interface CryptoFactory {

    int getProfileId();

    MessageDigest getDigestInstance();

    SecureRandom getSecureRandom();

    Symmetric getSymmetric();

    Asymmetric getAsymmetric();

    StandardKeyDerivation getStandardKeyDerivation();

    SCryptKeyDerivation getSCryptKeyDerivation();

    interface Asymmetric {
        KeyFactory getKeyFactory();

        KeyPair generateKeyPair();

        Cipher getInstance();

        Signing getSigning();

        interface Signing {
            XMLSignatureFactory getSignatureFactory();

            String getDigestMethodAlgorithm();

            String getTransformAlgorithm();

            String getCanonicalizationMethodAlgorithm();

            String getSignatureMethodAlgorithm();
        }
    }

    interface StandardKeyDerivation {
        SecretKeyFactory getSecretKeyFactory();

        int getSaltLength();

        int getIterations();
    }

    interface SCryptKeyDerivation {
        int getSaltLength();
        int getIterationFactor();
        int getMemoryFactor();
        int getParallelisation();
        int getKeyLength();
    }

    interface Symmetric {
        KeyGenerator getKeyGenerator();

        Cipher getInstance();

        int getIvLength();
    }
}
