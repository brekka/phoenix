/*
 * Copyright 2013 the original author or authors.
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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.brekka.xml.phoenix.v2.model.EnvironmentType;
import org.brekka.xml.phoenix.v2.model.EnvironmentType.Enum;

/**
 * Environment utilities
 *
 * @author Andrew Taylor (andrew@brekka.org)
 */
class EnviromentUtils {
    
    public static final Set<Enum> ENVIRONMENT_TYPES;
    
    static {
        Set<Enum> envTypes = identifyEnvironment();
        
        ENVIRONMENT_TYPES = Collections.unmodifiableSet(envTypes);
    }
    

    /**
     * @return
     */
    private static Set<Enum> identifyEnvironment() {
        Set<Enum> envTypes = new HashSet<>();
        String osName = System.getProperty("os.name");
        
        if (osName == null) {
            // Possibly a bad idea
            throw new IllegalStateException("Unable to read the operating system name");
        }
        
        osName = osName.toLowerCase();
        
        if (osName.startsWith("windows")) {
            envTypes.add(EnvironmentType.WINDOWS);
        } else if (osName.startsWith("linux")) {
            envTypes.add(EnvironmentType.LINUX);
        } else if (osName.startsWith("solaris")) {
            envTypes.add(EnvironmentType.SOLARIS);
        } else if (osName.startsWith("mac os x")) {
            envTypes.add(EnvironmentType.MACOSX);
        } 
        return envTypes;
    }
    
}
