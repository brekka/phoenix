package org.brekka.phoenix.core.services.impl.factory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.brekka.phoenix.core.PhoenixErrorCode;
import org.brekka.phoenix.core.PhoenixException;
import org.brekka.phoenix.core.services.CryptoFactory;
import org.brekka.xml.phoenix.v2.model.CryptoProfileDocument.CryptoProfile;

public class CryptoFactoryImpl implements CryptoFactory {

    private final int id;
    
    private final String messageDigestAlgorithm;
    
    private final SecureRandom secureRandom;
    
    private final Asymmetric asynchronous;
    
    private final StandardKeyDerivation standardKeyDerivation;
    
    private final SCryptKeyDerivation scryptKeyDerivation;
    
    private final Symmetric symmetric;
    
    public CryptoFactoryImpl(CryptoProfile cryptoProfile) {
        this(
            cryptoProfile.getID(),
            cryptoProfile.getMessageDigest().getStringValue(),
            cryptoProfile.getRandom().getStringValue(),
            new AsymmetricImpl(cryptoProfile.getAsymmetric()), 
            (cryptoProfile.getKeyDerivation().getStandard() != null ? new StandardKeyDerivationImpl(cryptoProfile.getKeyDerivation().getStandard()) : null), 
            (cryptoProfile.getKeyDerivation().getSCrypt() != null ? new SCriptKeyDerivationImpl(cryptoProfile.getKeyDerivation().getSCrypt()) : null),
            new SymmetricImpl(cryptoProfile.getSymmetric())
        );
    }
    
    public CryptoFactoryImpl(int id, String messageDigestAlgorithm, String secureRandomAlgorithm, 
            Asymmetric asynchronous, StandardKeyDerivation standardKeyDerivation, SCryptKeyDerivation scryptKeyDerivation,
            Symmetric synchronous) {
        this.id = id;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
        try {
            this.secureRandom = SecureRandom.getInstance(secureRandomAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new PhoenixException(PhoenixErrorCode.CP400, e, 
                    "Secure random algorithm '%s' not found", secureRandomAlgorithm);
        }
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

}
