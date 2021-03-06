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

package org.brekka.phoenix.api;

/**
 * Applications will refer to a given profile via an instance of this class. It's contract is simply to return the
 * unique number assigned to the profile.
 * 
 * @author Andrew Taylor (andrew@brekka.org)
 */
public interface CryptoProfile {

    public static final CryptoProfile DEFAULT = CryptoProfile.Static.of(0);

    /**
     * The number of this profile
     * 
     * @return
     */
    int getNumber();

    /**
     * For situations where the CryptoProfile cannot be retrieved directly from the service.
     */
    public static class Static implements CryptoProfile {

        private final int number;

        /**
         * @param number
         */
        private Static(int number) {
            this.number = number;
        }

        /**
         * @return the number
         */
        public int getNumber() {
            return number;
        }

        public static CryptoProfile of(int number) {
            return new Static(number);
        }
    }
}
