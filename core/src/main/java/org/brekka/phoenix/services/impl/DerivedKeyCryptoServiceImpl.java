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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.brekka.phoenix.PhoenixErrorCode;
import org.brekka.phoenix.PhoenixException;
import org.brekka.phoenix.api.CryptoProfile;
import org.brekka.phoenix.api.DerivedKey;
import org.brekka.phoenix.api.services.DerivedKeyCryptoService;
import org.brekka.phoenix.config.CryptoFactory.SCryptKeyDerivation;
import org.brekka.phoenix.config.CryptoFactory.StandardKeyDerivation;

import com.lambdaworks.crypto.SCrypt;

/**
 * TODO Description of DerivedKeyCryptoServiceImpl
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
public class DerivedKeyCryptoServiceImpl extends CryptoServiceSupport implements DerivedKeyCryptoService {

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.DerivedKeyCryptoService#apply(byte[], org.brekka.phoenix.api.CryptoProfile)
     */
    @Override
    public DerivedKey apply(byte[] key, CryptoProfile cryptoProfile) {
        CryptoProfileImpl profile = narrowProfile(cryptoProfile);
        StandardKeyDerivation standardKeyDerivation = profile.getStandardKeyDerivation();
        DerivedKey result;
        if (standardKeyDerivation == null) {
            result = applySCript(key, profile);
        } else {
            result = applyStandard(key, profile);
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.services.DerivedKeyCryptoService#check(byte[], org.brekka.phoenix.api.DerivedKey)
     */
    @Override
    public boolean check(byte[] key, DerivedKey derivedKey) {
        CryptoProfileImpl profile = narrowProfile(derivedKey.getProfile());
        StandardKeyDerivation standardKeyDerivation = profile.getStandardKeyDerivation();
        boolean result;
        if (standardKeyDerivation == null) {
            result = checkSCript(key, derivedKey, profile);
        } else {
            result = checkStandard(key, derivedKey, profile);
        }
        return result;
    }

    /**
     * @param key
     * @param derivedKey
     * @param profile
     */
    protected boolean checkStandard(byte[] key, DerivedKey derivedKey, CryptoProfileImpl profile) {
        StandardKeyDerivation standardKeyDerivation = profile.getStandardKeyDerivation();
        byte[] salt = derivedKey.getDerivedKey();
        byte[] derived;
        try {
            // Ugly hack, not planning on using standard anyway
            char[] pw = new String(key, "UTF-8").toCharArray();
            PBEKeySpec pbeKeySpec = new PBEKeySpec(pw, salt, standardKeyDerivation.getIterations());
            SecretKeyFactory secretKeyFactory = standardKeyDerivation.getSecretKeyFactory();
            SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);
            derived = pbeKey.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "Failed to perform encryption/decryption operation");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
        return Arrays.equals(derived, key);
    }

    /**
     * @param key
     * @param derivedKey
     * @param profile
     */
    protected boolean checkSCript(byte[] key, DerivedKey derivedKey, CryptoProfileImpl profile) {
        SCryptKeyDerivation sCryptKeyDerivation = profile.getSCryptKeyDerivation();
        byte[] salt = derivedKey.getSalt();
        int N = sCryptKeyDerivation.getIterationFactor();
        int r = sCryptKeyDerivation.getMemoryFactor();
        int p = sCryptKeyDerivation.getParallelisation();
        int dkLen = sCryptKeyDerivation.getKeyLength();
        byte[] derived;
        try {
            derived = SCrypt.scrypt(key, salt, N, r, p, dkLen);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "SCript error, profile %s", profile);
        }
        return Arrays.equals(derived, key);
    }

    /**
     * @param key
     * @param cryptoProfile
     */
    protected DerivedKey applyStandard(byte[] key, CryptoProfileImpl cryptoProfile) {
        StandardKeyDerivation standardKeyDerivation = cryptoProfile.getStandardKeyDerivation();
        byte[] derived;
        byte[] salt = generateSalt(standardKeyDerivation.getSaltLength(), cryptoProfile);
        try {
            // Ugly hack, not planning on using standard anyway
            char[] pw = new String(key, "UTF-8").toCharArray();
            PBEKeySpec pbeKeySpec = new PBEKeySpec(pw, salt, standardKeyDerivation.getIterations());
            SecretKeyFactory secretKeyFactory = standardKeyDerivation.getSecretKeyFactory();
            SecretKey pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);
            derived = pbeKey.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "Failed to perform encryption/decryption operation");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
        return new DerivedKeyImpl(cryptoProfile, null, salt, derived);
    }

    /**
     * @param key
     * @param cryptoProfile
     */
    protected DerivedKey applySCript(byte[] key, CryptoProfileImpl profile) {
        SCryptKeyDerivation sCryptKeyDerivation = profile.getSCryptKeyDerivation();
        byte[] salt = generateSalt(sCryptKeyDerivation.getSaltLength(), profile);
        int N = sCryptKeyDerivation.getIterationFactor();
        int r = sCryptKeyDerivation.getMemoryFactor();
        int p = sCryptKeyDerivation.getParallelisation();
        int dkLen = sCryptKeyDerivation.getKeyLength();
        byte[] derived;
        try {
            derived = SCrypt.scrypt(key, salt, N, r, p, dkLen);
        } catch (GeneralSecurityException e) {
            throw new PhoenixException(PhoenixErrorCode.CP300, e, 
                    "SCript error, profile %s", profile);
        }
        return new DerivedKeyImpl(profile, null, salt, derived);
    }
    
    protected byte[] generateSalt(int length, CryptoProfileImpl profile) {
        byte[] salt = new byte[length];
        profile.getSecureRandom().nextBytes(salt);
        return salt;
    }


}
