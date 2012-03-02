package org.brekka.phoenix;

public interface CryptoFactoryRegistry {

    CryptoFactory getDefault();
    
    CryptoFactory getFactory(int profileId);
}
