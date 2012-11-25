package org.brekka.phoenix.config;

public interface CryptoFactoryRegistry {

    CryptoFactory getDefault();
    
    CryptoFactory getFactory(int profileId);
}
