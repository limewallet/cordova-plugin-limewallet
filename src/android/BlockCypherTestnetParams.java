/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.latincoin.bitwallet;

import org.bitcoinj.core.NetworkParameters;

public class BlockCypherTestnetParams extends NetworkParameters {
    public BlockCypherTestnetParams() {
        super();
        addressHeader = 0x1b;
        p2shHeader    = 0x1f;

        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
    }

    @Override
    public String getPaymentProtocolId() {
      return "El ooooooooocho";
    }

    private static BlockCypherTestnetParams instance;
    public static synchronized BlockCypherTestnetParams get() {
        if (instance == null) {
            instance = new BlockCypherTestnetParams();
        }
        return instance;
    }
}
