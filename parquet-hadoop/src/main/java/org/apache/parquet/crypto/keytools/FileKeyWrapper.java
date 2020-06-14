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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.parquet.crypto.keytools.KeyToolkit.KeyEncryptionKey;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileKeyWrapper {
  private static final Logger LOG = LoggerFactory.getLogger(FileKeyWrapper.class);

  public static final int KEK_LENGTH = 16;
  public static final int KEK_ID_LENGTH = 16;

  // For every token: a map of MEK_ID to (KEK ID and KEK)
  private final TwoLevelCacheWithExpiration<String, KeyEncryptionKey> kekMapPerToken =
    KEKWriteCache.INSTANCE.getCache();
  private final long cacheCleanupPeriod;
  private final long cacheEntryLifetime;

  //A map of MEK_ID to (KEK ID and KEK) - for the current token
  private final ConcurrentMap<String, KeyEncryptionKey> KEKPerMasterKeyID;

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final KmsClient kmsClient;
  private final String kmsInstanceID;
  private final String kmsInstanceURL;
  private final FileKeyMaterialStore keyMaterialStore;
  private final Configuration hadoopConfiguration;
  private final SecureRandom random;
  private final boolean doubleWrapping;

  private short keyCounter;
  private String accessToken;

  public FileKeyWrapper(Configuration configuration, FileKeyMaterialStore keyMaterialStore) {
    this.hadoopConfiguration = configuration;
    this.keyMaterialStore = keyMaterialStore;

    random = new SecureRandom();
    keyCounter = 0;

    doubleWrapping =  hadoopConfiguration.getBoolean(KeyToolkit.DOUBLE_WRAPPING_PROPERTY_NAME, true);
    accessToken = hadoopConfiguration.getTrimmed(KeyToolkit.KEY_ACCESS_TOKEN_PROPERTY_NAME, KmsClient.DEFAULT_ACCESS_TOKEN);

    kmsInstanceID = hadoopConfiguration.getTrimmed(KeyToolkit.KMS_INSTANCE_ID_PROPERTY_NAME,
      KmsClient.DEFAULT_KMS_INSTANCE_ID);
    kmsInstanceURL = hadoopConfiguration.getTrimmed(KeyToolkit.KMS_INSTANCE_URL_PROPERTY_NAME, 
        RemoteKmsClient.DEFAULT_KMS_INSTANCE_URL);

    this.cacheEntryLifetime = 1000L * hadoopConfiguration.getLong(KeyToolkit.TOKEN_LIFETIME_PROPERTY_NAME,
      KeyToolkit.DEFAULT_CACHE_ENTRY_LIFETIME_SECONDS);
    this.cacheCleanupPeriod = cacheEntryLifetime;

    // Check caches upon each file writing (clean once in cacheEntryLifetime)
    KeyToolkit.checkKmsCacheForExpiredTokens(cacheEntryLifetime);
    kmsClient = KeyToolkit.getKmsClient(kmsInstanceID, configuration, accessToken, cacheEntryLifetime);

    if (doubleWrapping) {
      kekMapPerToken.checkCacheForExpiredTokens(cacheCleanupPeriod);
      KEKPerMasterKeyID = kekMapPerToken.getOrCreateInternalCache(accessToken, cacheEntryLifetime);
    } else {
      KEKPerMasterKeyID = null;
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("Creating file key wrapper. KmsClient: {}; KmsInstanceId: {}; KmsInstanceURL: {}; doubleWrapping: {}; "
          + "keyMaterialStore: {}; token snippet: {}", kmsClient, kmsInstanceID, kmsInstanceURL, doubleWrapping,
        keyMaterialStore, KeyToolkit.formatTokenForLog(accessToken));
    }
  }

  public byte[] getEncryptionKeyMetadata(byte[] dataKey, String masterKeyID, boolean isFooterKey) {
    return getEncryptionKeyMetadata(dataKey, masterKeyID, isFooterKey, null);
  }

  static void removeCacheEntriesForToken(String accessToken) {
      KEKWriteCache.INSTANCE.getCache().remove(accessToken);
  }

  static void removeCacheEntriesForAllTokens() {
    KEKWriteCache.INSTANCE.getCache().clear();
  }

  byte[] getEncryptionKeyMetadata(byte[] dataKey, String masterKeyID, boolean isFooterKey, String keyIdInFile) {
    if (null == kmsClient) {
      throw new ParquetCryptoRuntimeException("No KMS client available. See previous errors.");
    }

    KeyEncryptionKey keyEncryptionKey = null;
    String encodedWrappedDEK = null;
    if (!doubleWrapping) {
      encodedWrappedDEK = kmsClient.wrapKey(dataKey, masterKeyID);
    } else {
      // Find in cache, or generate KEK for Master Key ID
      keyEncryptionKey = KEKPerMasterKeyID.computeIfAbsent(masterKeyID,
          (k) -> createKeyEncryptionKey(masterKeyID));

      // Encrypt DEK with KEK
      byte[] AAD = keyEncryptionKey.getID();
      encodedWrappedDEK = KeyToolkit.wrapKeyLocally(dataKey, keyEncryptionKey.getBytes(), AAD);
    }

    // Pack all into key material JSON
    Map<String, String> keyMaterialMap = new HashMap<String, String>(10);
    keyMaterialMap.put(KeyToolkit.KEY_MATERIAL_TYPE_FIELD, KeyToolkit.KEY_MATERIAL_TYPE);
    if (isFooterKey) {
      keyMaterialMap.put(KeyToolkit.KMS_INSTANCE_ID_FIELD, kmsInstanceID);
      keyMaterialMap.put(KeyToolkit.KMS_INSTANCE_URL_FIELD, kmsInstanceURL);
    }
    if (null == keyMaterialStore) {
      keyMaterialMap.put(KeyToolkit.KEY_MATERIAL_INTERNAL_STORAGE_FIELD, "true");
    }
    keyMaterialMap.put(KeyToolkit.DOUBLE_WRAPPING_FIELD, Boolean.toString(doubleWrapping));
    keyMaterialMap.put(KeyToolkit.MASTER_KEY_ID_FIELD, masterKeyID);

    if (doubleWrapping) {
      keyMaterialMap.put(KeyToolkit.KEK_ID_FIELD, keyEncryptionKey.getEncodedID());
      keyMaterialMap.put(KeyToolkit.WRAPPED_KEK_FIELD, keyEncryptionKey.getWrappedWithCRK());
    }
    keyMaterialMap.put(KeyToolkit.WRAPPED_DEK_FIELD, encodedWrappedDEK);
    String keyMaterial;
    try {
      keyMaterial = OBJECT_MAPPER.writeValueAsString(keyMaterialMap);
    } catch (IOException e) {
      throw new ParquetCryptoRuntimeException("Failed to parse key material", e);
    }

    // Create key metadata
    byte[] keyMetadata = null;
    if (null != keyMaterialStore) {
      if (null == keyIdInFile) {
        if (isFooterKey) {
          keyIdInFile = KeyToolkit.FOOTER_KEY_ID_IN_FILE;
        } else {
          keyIdInFile = KeyToolkit.COLUMN_KEY_ID_IN_FILE_PREFIX + keyCounter;
          keyCounter++;
        }
      }
      keyMaterialStore.addKeyMaterial(keyIdInFile, keyMaterial);

      Map<String, String> keyMetadataMap = new HashMap<String, String>(2);
      keyMetadataMap.put(KeyToolkit.KEY_REFERENCE_FIELD, keyIdInFile);

      String keyMetadataString;
      try {
        keyMetadataString = OBJECT_MAPPER.writeValueAsString(keyMetadataMap);
      } catch (Exception e) {
        throw new ParquetCryptoRuntimeException("Failed to serialize key material", e);
      }

      keyMetadata = keyMetadataString.getBytes(StandardCharsets.UTF_8);
    }  else {
      keyMetadata  = keyMaterial.getBytes(StandardCharsets.UTF_8);
    }

    return keyMetadata;
  }

  private KeyEncryptionKey createKeyEncryptionKey(String masterKeyID) {
    byte[] kekBytes = new byte[KEK_LENGTH]; 
    random.nextBytes(kekBytes);

    byte[] kekID = new byte[KEK_ID_LENGTH];
    random.nextBytes(kekID);
    String encodedKEK_ID = Base64.getEncoder().encodeToString(kekID);

    // Encrypt KEK with Master key
    String encodedWrappedKEK = null;
    encodedWrappedKEK = kmsClient.wrapKey(kekBytes, masterKeyID);

    return new KeyEncryptionKey(kekBytes, encodedKEK_ID, kekID, encodedWrappedKEK);
  }

  public enum KEKWriteCache {
    INSTANCE;

    private final TwoLevelCacheWithExpiration<String, KeyEncryptionKey> cache =
      new TwoLevelCacheWithExpiration<>(KeyToolkit.INITIAL_PER_TOKEN_CACHE_SIZE);

    public TwoLevelCacheWithExpiration< String, KeyEncryptionKey> getCache() {
      return cache;
    }
  }
}