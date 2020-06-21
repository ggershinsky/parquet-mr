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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Concurrent two-level cache with expiration of internal caches according to token lifetime.
 * External cache is per token, internal is per K.
 * Wrapper class around:
 *   ConcurrentMap<String, ExpiringCacheEntry<ConcurrentMap<K, V>>>
 *
 * @param <K> Key for the internal cache
 * @param <V> Value
 */
public class TwoLevelCacheWithExpiration<K, V> {

  private static final long CACHE_CLEANUP_GRACE_PERIOD = 60L * 1000; // grace period of 1 minute;

  private final ConcurrentMap<String, ExpiringCacheEntry<ConcurrentMap<K, V>>> cache;
  private volatile long lastCacheCleanupTimestamp;

  public TwoLevelCacheWithExpiration(int initialSize) {
    this.cache = new ConcurrentHashMap<>(initialSize);
    this.lastCacheCleanupTimestamp = System.currentTimeMillis() + CACHE_CLEANUP_GRACE_PERIOD;
  }

  /**
   * Create cache for the specified access token.
   * @param accessToken
   * @param cacheEntryLifetime should correspond to token lifetime
   * @return
   */
  public ConcurrentMap<K,V> getOrCreateInternalCache(String accessToken, long cacheEntryLifetime) {
    ExpiringCacheEntry<ConcurrentMap<K, V>> externalCacheEntry = cache.compute(accessToken, (token, cacheEntry) -> {
      if ((null == cacheEntry) || cacheEntry.isExpired()) {
        return new ExpiringCacheEntry<>(new ConcurrentHashMap<K, V>(), cacheEntryLifetime);
      } else {
        return cacheEntry;
      }
    });
    return externalCacheEntry.getCachedItem();
  }

  public void removeCacheEntriesForToken(String accessToken) {
      cache.remove(accessToken);
  }

  public void removeCacheEntriesForAllTokens() {
      cache.clear();
  }

  public void checkCacheForExpiredTokens(long cacheCleanupPeriod) {
    long now = System.currentTimeMillis();

    if (now > (lastCacheCleanupTimestamp + cacheCleanupPeriod)) {
      synchronized (cache) {
        if (now > (lastCacheCleanupTimestamp + cacheCleanupPeriod)) {
          removeExpiredEntriesFromCache();
          lastCacheCleanupTimestamp = now + cacheCleanupPeriod;
        }
      }
    }
  }

  public void removeExpiredEntriesFromCache() {
    cache.values().removeIf(cacheEntry -> cacheEntry.isExpired());
  }

  public void remove(String accessToken) {
    cache.remove(accessToken);
  }

  public void clear() {
    cache.clear();
  }
}
