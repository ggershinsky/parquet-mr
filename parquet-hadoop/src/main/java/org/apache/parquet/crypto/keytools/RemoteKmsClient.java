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



package org.apache.parquet.crypto.keytools;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.crypto.KeyAccessDeniedException;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;


public abstract class RemoteKmsClient implements KmsClient {
  protected String kmsInstanceID;
  protected String kmsURL;
  protected Boolean isWrapLocally;

  private final int INITIAL_KEY_CACHE_SIZE = 10;
  // MasterKey cache: master keys per key ID (per KMS Client). For local wrapping only.
  private Map<String, byte[]> masterKeyCache;

  @Override
  public void initialize(Configuration configuration, String kmsInstanceID) {
    this.kmsInstanceID = kmsInstanceID;
    this.kmsURL = configuration.getTrimmed(KeyTookit.KMS_INSTANCE_URL_PROPERTY_NAME);

    this.isWrapLocally = configuration.getBoolean(KeyTookit.WRAP_LOCALLY_PROPERTY_NAME, false);
    if (isWrapLocally) {
      masterKeyCache = new HashMap<>(INITIAL_KEY_CACHE_SIZE);
    }

    initializeInternal(configuration);
  }

  @Override
  public String wrapKey(byte[] dataKey, String masterKeyIdentifier) throws KeyAccessDeniedException {
    if (isWrapLocally) {
      byte[] masterKey = getKeyFromCacheOrServer(masterKeyIdentifier);
      byte[] AAD = masterKeyIdentifier.getBytes(StandardCharsets.UTF_8);
      return KeyTookit.wrapKeyLocally(dataKey, masterKey, AAD);
    } else {
      return wrapKeyInServer(dataKey, masterKeyIdentifier);
    }
  }

  @Override
  public byte[] unwrapKey(String wrappedKey, String masterKeyIdentifier) throws KeyAccessDeniedException {
    if (isWrapLocally) {
      byte[] masterKey = getKeyFromCacheOrServer(masterKeyIdentifier);
      byte[] AAD = masterKeyIdentifier.getBytes(StandardCharsets.UTF_8);
      return KeyTookit.unwrapKeyLocally(wrappedKey, masterKey, AAD);
    } else {
      return unwrapKeyInServer(wrappedKey, masterKeyIdentifier);
    }
  }

  private byte[] getKeyFromCacheOrServer(String keyIdentifier) {
    synchronized (masterKeyCache) {
      byte[] masterKey = masterKeyCache.get(keyIdentifier);
      if (null == masterKey) {
        masterKey = getMasterKeyFromServer(keyIdentifier);
        masterKeyCache.put(keyIdentifier, masterKey);
      }
      return masterKey;
    }
  }

  /**
   * Wrap a key with the master key in the remote KMS server.
   * 
   * If your KMS client code throws runtime exceptions related to access/permission problems
   * (such as Hadoop AccessControlException), catch them and throw the KeyAccessDeniedException.
   * 
   * @param keyBytes: key bytes to be wrapped
   * @param masterKeyIdentifier: a string that uniquely identifies the master key in a KMS instance
   * @return wrappedKey: Encrypts key bytes with the master key, encodes the result  and potentially adds a KMS-specific metadata.
   * @throws KeyAccessDeniedException unauthorized to encrypt with the given master key
   * @throws UnsupportedOperationException KMS does not support in-server wrapping 
   */
  protected abstract String wrapKeyInServer(byte[] keyBytes, String masterKeyIdentifier) 
      throws KeyAccessDeniedException, UnsupportedOperationException;

  /**
   * Unwrap a key with the master key in the remote KMS server. 
   * 
   * If your KMS client code throws runtime exceptions related to access/permission problems
   * (such as Hadoop AccessControlException), catch them and throw the KeyAccessDeniedException.
   * 
   * @param wrappedKey String produced by wrapKey operation
   * @param masterKeyIdentifier: a string that uniquely identifies the master key in a KMS instance
   * @return key bytes
   * @throws KeyAccessDeniedException unauthorized to unwrap with the given master key
   * @throws UnsupportedOperationException KMS does not support in-server unwrapping 
   */
  protected abstract byte[] unwrapKeyInServer(String wrappedKey, String masterKeyIdentifier) 
      throws KeyAccessDeniedException, UnsupportedOperationException;
  
  /**
   * Get master key from the remote KMS server.
   * Required only for local wrapping. No need to implement if KMS supports in-server wrapping/unwrapping.
   * 
   * If your KMS client code throws runtime exceptions related to access/permission problems
   * (such as Hadoop AccessControlException), catch them and throw the KeyAccessDeniedException.
   * 
   * @param masterKeyIdentifier: a string that uniquely identifies the master key in a KMS instance
   * @throws KeyAccessDeniedException unauthorized to get the master key
   * @throws UnsupportedOperationException If not implemented, or KMS does not support key fetching 
   */
  protected abstract byte[] getMasterKeyFromServer(String masterKeyIdentifier) 
      throws KeyAccessDeniedException, UnsupportedOperationException;

  /**
   * Pass configuration with KMS-specific parameters.
   * @param configuration Hadoop configuration
   */
  protected abstract void initializeInternal(Configuration configuration) 
      throws KeyAccessDeniedException;
}