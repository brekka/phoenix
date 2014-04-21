/**
 * Copyright (c) 2014 Digital Shadows Ltd.
 */
package org.brekka.phoenix.core.services.impl.factory;

import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.brekka.phoenix.core.services.CryptoFactory.Asymmetric.Signing;
import org.brekka.xml.phoenix.v2.model.SigningType;

/**
 * @author Andrew Taylor (andy@digitalshadows.com)
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
