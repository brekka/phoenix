package org.brekka.phoenix.impl;

import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brekka.phoenix.CryptoFactory;
import org.brekka.phoenix.CryptoFactoryRegistry;
import org.brekka.xml.phoenix.v1.model.CryptoProfileDocument.CryptoProfile;
import org.brekka.xml.phoenix.v1.model.CryptoProfileRegistryDocument;
import org.brekka.xml.phoenix.v1.model.CryptoProfileRegistryDocument.CryptoProfileRegistry;

public class CryptoFactoryRegistryImpl implements CryptoFactoryRegistry {

    private CryptoFactory defaultProfile;
    
    private Map<Integer, CryptoFactory> profileMap = new HashMap<>();
    
    public CryptoFactoryRegistryImpl(CryptoFactory defaultProfile, CryptoFactory... others) {
        this.defaultProfile = defaultProfile;
        profileMap.put(defaultProfile.getProfileId(), defaultProfile);
        for (CryptoFactory cryptoProfile : others) {
            profileMap.put(cryptoProfile.getProfileId(), cryptoProfile);
        }
    }
    
    @Override
    public CryptoFactory getDefault() {
        return defaultProfile;
    }

    @Override
    public CryptoFactory getFactory(int profileId) {
        return profileMap.get(profileId);
    }
    
    public static CryptoFactoryRegistry createRegistry(CryptoProfileRegistryDocument doc) {
        Security.addProvider(new BouncyCastleProvider());
        
        CryptoFactory defaultFactory = null;
        
        CryptoProfileRegistry cryptoProfileRegistry = doc.getCryptoProfileRegistry();
        List<CryptoProfile> cryptoProfileList = cryptoProfileRegistry.getCryptoProfileList();
        List<CryptoFactory> cryptoFactories = new ArrayList<>(cryptoProfileList.size());
        for (CryptoProfile cryptoProfile : cryptoProfileList) {
            CryptoFactory factory = new CryptoFactoryImpl(cryptoProfile);
            if (cryptoProfile.getID() == cryptoProfileRegistry.getDefaultProfileID()) {
                defaultFactory = factory;
            } else {
                cryptoFactories.add(factory); 
            }
        }
        return new CryptoFactoryRegistryImpl(defaultFactory, cryptoFactories.toArray(new CryptoFactory[cryptoFactories.size()]));
    }

}
