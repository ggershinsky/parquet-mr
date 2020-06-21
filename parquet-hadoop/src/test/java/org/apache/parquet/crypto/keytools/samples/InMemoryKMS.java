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
package org.apache.parquet.crypto.keytools.samples;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.parquet.crypto.KeyAccessDeniedException;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.parquet.crypto.keytools.RemoteKmsClient;
import org.apache.parquet.crypto.keytools.KeyToolkit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a mock class, built for testing only. Don't use it as an example of KmsClient implementation.
 * (VaultClient is the sample implementation).
 */
public class InMemoryKMS extends RemoteKmsClient {
  private static final Logger LOG = LoggerFactory.getLogger(InMemoryKMS.class);

  public static final String KEY_LIST_PROPERTY_NAME = "encryption.key.list";
  public static final String NEW_KEY_LIST_PROPERTY_NAME = "new.encryption.key.list";

  private Map<String,byte[]> masterKeyMap;
  private Map<String,byte[]> newMasterKeyMap;
  
  void startKeyRotation() {
    String[] newMasterKeys = hadoopConfiguration.getTrimmedStrings(NEW_KEY_LIST_PROPERTY_NAME);
    if (null == newMasterKeys || newMasterKeys.length == 0) {
      throw new ParquetCryptoRuntimeException("No encryption key list");
    }
    newMasterKeyMap = parseKeyList(newMasterKeys);
  }
  
  void finishKeyRotation() {
    masterKeyMap = newMasterKeyMap;
  }

  @Override
  protected void initializeInternal() {
    // Parse master  keys
    String[] masterKeys = hadoopConfiguration.getTrimmedStrings(KEY_LIST_PROPERTY_NAME);
    if (null == masterKeys || masterKeys.length == 0) {
      throw new ParquetCryptoRuntimeException("No encryption key list");
    }
    masterKeyMap = parseKeyList(masterKeys);
    
    newMasterKeyMap = masterKeyMap;
  }

  private static Map<String, byte[]> parseKeyList(String[] masterKeys) {
    Map<String,byte[]> keyMap = new HashMap<>();

    int nKeys = masterKeys.length;
    for (int i=0; i < nKeys; i++) {
      String[] parts = masterKeys[i].split(":");
      String keyName = parts[0].trim();
      if (parts.length != 2) {
        throw new IllegalArgumentException("Key '" + keyName + "' is not formatted correctly");
      }
      String key = parts[1].trim();
      try {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        keyMap.put(keyName, keyBytes);
      } catch (IllegalArgumentException e) {
        LOG.warn("Could not decode key '" + keyName + "'!");
        throw e;
      }
    }
    return keyMap;
  }

  @Override
  protected String wrapKeyInServer(byte[] keyBytes, String masterKeyIdentifier)
      throws KeyAccessDeniedException, UnsupportedOperationException {
    byte[] masterKey = newMasterKeyMap.get(masterKeyIdentifier);
    if (null == masterKey) {
      throw new ParquetCryptoRuntimeException("Key not found: " + masterKeyIdentifier);
    }
    byte[] AAD = masterKeyIdentifier.getBytes(StandardCharsets.UTF_8);
    return KeyToolkit.encryptKeyLocally(keyBytes, masterKey, AAD);
  }

  @Override
  protected byte[] unwrapKeyInServer(String wrappedKey, String masterKeyIdentifier)
      throws KeyAccessDeniedException, UnsupportedOperationException {
    byte[] masterKey = masterKeyMap.get(masterKeyIdentifier);
    if (null == masterKey) {
      throw new ParquetCryptoRuntimeException("Key not found: " + masterKeyIdentifier);
    }
    byte[] AAD = masterKeyIdentifier.getBytes(StandardCharsets.UTF_8);
    return KeyToolkit.decryptKeyLocally(wrappedKey, masterKey, AAD);
  }

  @Override
  protected byte[] getMasterKeyFromServer(String masterKeyIdentifier)
      throws KeyAccessDeniedException, UnsupportedOperationException {
    return newMasterKeyMap.get(masterKeyIdentifier);
  }
}