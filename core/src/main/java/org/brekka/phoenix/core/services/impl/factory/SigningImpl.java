/*
 * Copyright 2014 the original author or authors.
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

import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.brekka.phoenix.core.services.CryptoFactory.Asymmetric.Signing;
import org.brekka.xml.phoenix.v2.model.SigningType;

/**
 * @author Andrew Taylor (andrew@brekka.org)
 *
 */
public class SigningImpl implements Signing {

    private final XMLSignatureFactory signatureFactory;

    private final String digestMethodAlgorithm;
    private final String transformAlgorithm;
    private final String canonicalizationMethodAlgorithm;
    private final String signatureMethodAlgorithm;

    /**
     * @param signing
     */
    public SigningImpl(final SigningType signing) {
        this(signing.getSignatureFactory(), signing.getDigestMethod(), signing.getTransform(), signing.getCanonicalizationMethod(), signing.getSignatureMethod());
    }

    /**
     * @param signatureFactory
     * @param digestMethodAlgorithm
     * @param transformAlgorithm
     * @param canonicalizationMethodAlgorithm
     * @param signatureMethodAlgorithm
     */
    public SigningImpl(final String signatureFactoryMechanism, final String digestMethodAlgorithm, final String transformAlgorithm,
            final String canonicalizationMethodAlgorithm, final String signatureMethodAlgorithm) {
        this.signatureFactory = XMLSignatureFactory.getInstance(signatureFactoryMechanism);
        this.digestMethodAlgorithm = digestMethodAlgorithm;
        this.transformAlgorithm = transformAlgorithm;
        this.canonicalizationMethodAlgorithm = canonicalizationMethodAlgorithm;
        this.signatureMethodAlgorithm = signatureMethodAlgorithm;
    }



    /* (non-Javadoc)
     * @see org.brekka.phoenix.core.services.CryptoFactory.Asymmetric.Signing#getSignatureFactory()
     */
    @Override
    public XMLSignatureFactory getSignatureFactory() {
        return this.signatureFactory;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.core.services.CryptoFactory.Asymmetric.Signing#getDigestMethodAlgorithm()
     */
    @Override
    public String getDigestMethodAlgorithm() {
        return this.digestMethodAlgorithm;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.core.services.CryptoFactory.Asymmetric.Signing#getTransformAlgorithm()
     */
    @Override
    public String getTransformAlgorithm() {
        return this.transformAlgorithm;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.core.services.CryptoFactory.Asymmetric.Signing#getCanonicalizationMethodAlgorithm()
     */
    @Override
    public String getCanonicalizationMethodAlgorithm() {
        return this.canonicalizationMethodAlgorithm;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.core.services.CryptoFactory.Asymmetric.Signing#getSignatureMethodAlgorithm()
     */
    @Override
    public String getSignatureMethodAlgorithm() {
        return this.signatureMethodAlgorithm;
    }

}
