/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.parquet.crypto.mocks;


import org.apache.parquet.crypto.KeyAccessDeniedException;
import org.apache.parquet.crypto.keytools.KeyToolkit;
import org.apache.parquet.crypto.keytools.RemoteKmsClient;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class RemoteKmsClientMock extends RemoteKmsClient {
  private static final byte[] FOOTER_MASTER_KEY = "0123456789012345".getBytes(StandardCharsets.UTF_8);
  private static final String FOOTER_MASTER_KEY_ID = "kf";
  private static final byte[][] COLUMN_MASTER_KEYS = {
    "1234567890123450".getBytes(StandardCharsets.UTF_8),
    "1234567890123451".getBytes(StandardCharsets.UTF_8),
    "1234567890123452".getBytes(StandardCharsets.UTF_8),
    "1234567890123453".getBytes(StandardCharsets.UTF_8),
    "1234567890123454".getBytes(StandardCharsets.UTF_8),
    "1234567890123455".getBytes(StandardCharsets.UTF_8)};
  private static final String[] COLUMN_MASTER_KEY_IDS = { "kc1", "kc2", "kc3", "kc4", "kc5", "kc6"};
  final static byte[] AAD = FOOTER_MASTER_KEY_ID.getBytes(StandardCharsets.UTF_8);

  private Map<String, byte[]> keyMap;


  @Override
  protected void initializeInternal() throws KeyAccessDeniedException {
    keyMap = new HashMap<>(7);
    keyMap.put(FOOTER_MASTER_KEY_ID, FOOTER_MASTER_KEY);
    keyMap.put(COLUMN_MASTER_KEY_IDS[0], COLUMN_MASTER_KEYS[0]);
    keyMap.put(COLUMN_MASTER_KEY_IDS[1], COLUMN_MASTER_KEYS[1]);
    keyMap.put(COLUMN_MASTER_KEY_IDS[2], COLUMN_MASTER_KEYS[2]);
    keyMap.put(COLUMN_MASTER_KEY_IDS[3], COLUMN_MASTER_KEYS[3]);
    keyMap.put(COLUMN_MASTER_KEY_IDS[4], COLUMN_MASTER_KEYS[4]);
    keyMap.put(COLUMN_MASTER_KEY_IDS[5], COLUMN_MASTER_KEYS[5]);
  }

  @Override
  protected String wrapKeyInServer(byte[] keyBytes, String masterKeyIdentifier) throws KeyAccessDeniedException, UnsupportedOperationException {
    return KeyToolkit.encryptKeyLocally(keyBytes, keyMap.get(masterKeyIdentifier), AAD);
  }

  @Override
  protected byte[] unwrapKeyInServer(String wrappedKey, String masterKeyIdentifier) throws KeyAccessDeniedException, UnsupportedOperationException {
    return KeyToolkit.decryptKeyLocally(wrappedKey, keyMap.get(masterKeyIdentifier), AAD);
  }

  @Override
  protected byte[] getMasterKeyFromServer(String masterKeyIdentifier) throws KeyAccessDeniedException, UnsupportedOperationException {
    return keyMap.get(masterKeyIdentifier);
  }
}
