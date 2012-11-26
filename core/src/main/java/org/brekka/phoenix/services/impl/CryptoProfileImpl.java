package org.brekka.phoenix.services.impl;

import org.brekka.phoenix.config.CryptoFactory;

class CryptoProfileImpl implements org.brekka.phoenix.api.CryptoProfile {

    private final CryptoFactory cryptoFactory;
    
    public CryptoProfileImpl(CryptoFactory cryptoFactory) {
        this.cryptoFactory = cryptoFactory;
    }

    /* (non-Javadoc)
     * @see org.brekka.phoenix.api.CryptoProfile#getNumber()
     */
    @Override
    public int getNumber() {
        return cryptoFactory.getProfileId();
    }
    
    /**
     * @return the cryptoFactory
     */
    public CryptoFactory getFactory() {
        return cryptoFactory;
    }
    
}
