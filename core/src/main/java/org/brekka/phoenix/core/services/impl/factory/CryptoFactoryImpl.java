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

package org.brekka.phoenix.core.services.impl.factory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.brekka.phoenix.core.PhoenixErrorCode;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.services.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.CryptoProfileDocument.CryptoProfile;
import org.brekka.xml.phoenix.v2.model.EnvironmentSpecificAlgorithmType;
import org.brekka.xml.phoenix.v2.model.EnvironmentType;
import org.brekka.xml.phoenix.v2.model.EnvironmentType.Enum;

public class CryptoFactoryImpl implements CryptoFactory {

    private final int id;
    
    private final String messageDigestAlgorithm;
    
    private final SecureRandom secureRandom;
    
    private final Asymmetric asynchronous;
    
    private final StandardKeyDerivation standardKeyDerivation;
    
    private final SCryptKeyDerivation scryptKeyDerivation;
    
    private final Symmetric symmetric;
    
    public CryptoFactoryImpl(int id, String messageDigestAlgorithm, SecureRandom secureRandom,
            Asymmetric asynchronous, StandardKeyDerivation standardKeyDerivation, SCryptKeyDerivation scryptKeyDerivation,
            Symmetric synchronous) {
        this.id = id;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
        this.secureRandom = secureRandom;
        this.asynchronous = asynchronous;
        this.standardKeyDerivation = standardKeyDerivation;
        this.scryptKeyDerivation = scryptKeyDerivation;
        this.symmetric = synchronous;
    }

    @Override
    public int getProfileId() {
        return id;
    }

    @Override
    public MessageDigest getDigestInstance() {
        try {
            return MessageDigest.getInstance(messageDigestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new PhoenixException(PhoenixErrorCode.CP100, e, 
                    "Message digest algorithm '%s' not found", messageDigestAlgorithm);
        }
    }
    
    @Override
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    @Override
    public Asymmetric getAsymmetric() {
        return asynchronous;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.CryptoFactory#getSCryptKeyDerivation()
     */
    @Override
    public SCryptKeyDerivation getSCryptKeyDerivation() {
        return scryptKeyDerivation;
    }
    
    /* (non-Javadoc)
     * @see org.brekka.phoenix.CryptoFactory#getStandardKeyDerivation()
     */
    @Override
    public StandardKeyDerivation getStandardKeyDerivation() {
        return standardKeyDerivation;
    }

    @Override
    public Symmetric getSymmetric() {
        return symmetric;
    }

    public static CryptoFactory newInstance(CryptoProfile cryptoProfile) {
        String randomAlgorithm = identifyForEnvironment(cryptoProfile.getRandomList());
        try {
            SecureRandom secureRandom = SecureRandom.getInstance(randomAlgorithm);
            return new CryptoFactoryImpl(
                cryptoProfile.getID(),
                cryptoProfile.getMessageDigest().getStringValue(),
                secureRandom,
                new AsymmetricImpl(secureRandom, cryptoProfile.getAsymmetric()), 
                (cryptoProfile.getKeyDerivation().getStandard() != null ? new StandardKeyDerivationImpl(cryptoProfile.getKeyDerivation().getStandard()) : null), 
                (cryptoProfile.getKeyDerivation().getSCrypt() != null ? new SCriptKeyDerivationImpl(cryptoProfile.getKeyDerivation().getSCrypt()) : null),
                new SymmetricImpl(secureRandom, cryptoProfile.getSymmetric())
            );
        } catch (NoSuchAlgorithmException e) {
            throw new PhoenixException(PhoenixErrorCode.CP400, e, 
                    "Secure random algorithm '%s' not found", randomAlgorithm);
        }
    }

    /**
     * @param randomList
     * @return
     */
    private static String identifyForEnvironment(List<EnvironmentSpecificAlgorithmType> algorithmList) {
        Set<EnvironmentType.Enum> available = EnviromentUtils.ENVIRONMENT_TYPES;
        EnvironmentSpecificAlgorithmType defaultAlgorithm = null;
        for (EnvironmentSpecificAlgorithmType algorithm : algorithmList) {
            if (!algorithm.isSetEnvironment()
                    || algorithm.getEnvironment().equals(EnvironmentType.OTHER)) {
                defaultAlgorithm = algorithm;
            } else if (available.contains(algorithm.getEnvironment())) {
                // Specific to our environment
                return algorithm.getStringValue();
            }
        }
        if (defaultAlgorithm == null) {
            throw new PhoenixException(PhoenixErrorCode.CP451, "No default algorithm found and no match for environment '%s'", available);
        }
        return defaultAlgorithm.getStringValue();
    }
}
