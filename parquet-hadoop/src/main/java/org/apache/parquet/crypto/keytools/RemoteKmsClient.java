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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.crypto.KeyAccessDeniedException;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An abstract class for implementation of a remote-KMS client.
 * Both KMS instance ID and KMS URL need to be defined in order to access such a KMS.
 * The concrete implementation should implement getKeyFromServer() and/or
 * wrapDataKeyInServer() with unwrapDataKeyInServer() methods.
 */
public abstract class RemoteKmsClient implements KmsClient {
  private static final long KEY_CACHE_EXPIRATION_TIME = 10 * 60 * 1000; // 10 minutes

  protected String kmsInstanceID;
  protected String kmsURL;
  // Example value that matches the pattern:    vault-instance-1: http://127.0.0.1:8200
  protected Pattern kmsUrlListItemPattern = Pattern.compile("^(\\S+)\\s*:\\s*(\\w*://\\S+)$");

  // Key cache per KmsClient instance, since it is shared by multiple threads with the same
  // KMS instance id and access token
  private final int INITIAL_KEY_CACHE_SIZE = 10;
  private final Map<String, SelfDestructiveKeyCacheEntry> keyCache = new HashMap<String, SelfDestructiveKeyCacheEntry>(INITIAL_KEY_CACHE_SIZE);

  /**
   *  Initialize the KMS Client with KMS instance ID and URL.
   *  When reading a parquet file, the KMS instance ID can be either specified in configuration
   *  or read from parquet file metadata, or default if there is a default value for this KMS type.
   *  When writing a parquet file, the KMS instance ID has to be specified in configuration
   *  or default if there is a default value for this KMS type.
   *  The KMS URL has to be specified in configuration either specifically or as a mapping of KMS instance ID to KMS URL,
   *  e.g. { "kmsInstanceID1": "kmsURL1", "kmsInstanceID2" : "kmsURL2" }, but not both.
   * @param configuration Hadoop configuration
   * @param kmsInstanceID instance ID of the KMS managed by this KmsClient. When reading a parquet file, the KMS
   *                      instance ID can be either specified in configuration or read from parquet file metadata.
   *                      When writing a parquet file, the KMS instance ID has to be specified in configuration.
   *                      KMSClient implementation could have a default value for this.
   * @throws IOException
   */
  @Override
  public void initialize(Configuration configuration, String kmsInstanceID) throws IOException {
    this.kmsInstanceID = kmsInstanceID;
    setKmsURL(configuration);
    initializeInternal(configuration);
  }

  protected abstract void initializeInternal(Configuration configuration) throws IOException;

  private void setKmsURL(Configuration configuration) throws IOException {
    final String kmsUrlProperty = configuration.getTrimmed("encryption.kms.instance.url");
    final String[] kmsUrlList = configuration.getTrimmedStrings("encryption.kms.instance.url.list");
    if (StringUtils.isEmpty(kmsUrlProperty) && ArrayUtils.isEmpty(kmsUrlList)) {
      throw new IOException("KMS URL is not set.");
    }
    if (!StringUtils.isEmpty(kmsUrlProperty) && !ArrayUtils.isEmpty(kmsUrlList)) {
      throw new IOException("KMS URL is ambiguous: " +
              "it should either be set in encryption.kms.instance.url or in encryption.kms.instance.url.list");
    }
    if (!StringUtils.isEmpty(kmsUrlProperty)) {
      kmsURL = kmsUrlProperty;
    } else {
      if (StringUtils.isEmpty(kmsInstanceID) ) {
        throw new IOException("Missing kms instance id value. Cannot find a matching KMS URL mapping.");
      }
      Map<String, String> kmsUrlMap = new HashMap<String, String>(kmsUrlList.length);
      int nKeys = kmsUrlList.length;
      for (int i=0; i < nKeys; i++) {
        Matcher m = kmsUrlListItemPattern.matcher(kmsUrlList[i]);
        if (!m.matches() || (m.groupCount() != 2)) {
          throw new IOException(String.format("String %s doesn't match pattern %s for KMS URL mapping",
                  kmsUrlList[i], kmsUrlListItemPattern.toString()));
        }
        String instanceID = m.group(1);
        String kmsURL = m.group(2);
        //TODO check parts
        kmsUrlMap.put(instanceID, kmsURL);
      }
      kmsURL = kmsUrlMap.get(kmsInstanceID);
      if (StringUtils.isEmpty(kmsURL) ) {
        throw new IOException(String.format("Missing KMS URL for kms instance ID [%s] in KMS URL mapping",
                kmsInstanceID));
      }
    }
  }


  @Override
  public abstract boolean supportsServerSideWrapping();


  /**
   * Get a standard key from server. First check if the key is in local key cache and the cache entry is not expired.
   * If it is - return the key from the cache entry. Otherwise - getKeyFromServerRemoteCall.
   * @param keyIdentifier: a string that uniquely identifies the key in KMS:
   * ranging from a simple key ID, to e.g. a JSON with key ID, KMS instance etc.
   * @return
   * @throws UnsupportedOperationException
   * @throws KeyAccessDeniedException
   * @throws IOException
   */
  @Override
  public byte[] getKeyFromServer(String keyIdentifier)
          throws KeyAccessDeniedException, IOException {
    byte[] keyCopy;
    synchronized (keyCache) {
      SelfDestructiveKeyCacheEntry keyCacheEntry = keyCache.get(keyIdentifier);
      byte[] key;
      if ((null == keyCacheEntry) || (null == (key = keyCacheEntry.getEncryptionKey())) || !keyCacheEntry.isValid()) {
        // We try to minimize calls to this expensive operation using the cache
        key = getKeyFromServerRemoteCall(keyIdentifier);
        final long expirationTimestamp = System.currentTimeMillis() + KEY_CACHE_EXPIRATION_TIME;
        // Add a new cache entry or overwrite an expired one
        keyCache.put(keyIdentifier, new SelfDestructiveKeyCacheEntry(key, expirationTimestamp));
      }
      keyCopy = Arrays.copyOf(key, key.length);
    }
    return keyCopy;
  }

  /**
   * Get a standard key from server - call the remote server, without using the key cache.
   * This method should be implemented by the concrete RemoteKmsClient implementation,
   * otherwise it throws an UnsupportedOperationException.
   */
  protected byte[] getKeyFromServerRemoteCall(String keyIdentifier) throws IOException, KeyAccessDeniedException, UnsupportedOperationException {
    throw new UnsupportedOperationException();
  }

  /**
   * This method should be implemented by the concrete RemoteKmsClient implementation,
   * otherwise it throws an UnsupportedOperationException.
   */
  @Override
  public String wrapDataKeyInServer(byte[] dataKey, String masterKeyIdentifier)
      throws UnsupportedOperationException, KeyAccessDeniedException, IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * This method should be implemented by the concrete RemoteKmsClient implementation,
   * otherwise it throws an UnsupportedOperationException.
   */
  @Override
  public byte[] unwrapDataKeyInServer(String wrappedDataKey, String masterKeyIdentifier)
      throws UnsupportedOperationException, KeyAccessDeniedException, IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Self destructive key cache entry - if getKey is called on an expired entry, then the key is automatically wiped-out
   */
  private static class SelfDestructiveKeyCacheEntry {

    private byte[] encryptionKey;
    private final long expirationTimestamp;

    public SelfDestructiveKeyCacheEntry(byte[] encryptionKey, long expirationTimestamp) {
      this.encryptionKey = encryptionKey;
      this.expirationTimestamp = expirationTimestamp;
    }

    /**
     * Returns the key, if the cache entry is still valid (not expired).
     * If it not valid - wipes out the key and sets it to null.
     * @return
     */
    public byte[] getEncryptionKey() {
      if (!isValid()) {
        byte[] expiredKey = encryptionKey;
        encryptionKey = null;
        FileKeyManager.wipeKey(expiredKey);
      }
      return encryptionKey;
    }

    public long getExpirationTimestamp() {
      return expirationTimestamp;
    }

    /**
     * Returns true if the cache entry is not expired yet.
     * @return
     */
    public boolean isValid() {
      final long now = System.currentTimeMillis();
      return (now < expirationTimestamp);
    }
  }
}
