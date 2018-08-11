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


package org.apache.parquet.crypto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class FileDecryptionProperties {

  private byte[] footerKeyBytes;
  private DecryptionKeyRetriever keyRetriever;
  private AADRetriever aadRetriever;
  
  private byte[] aadBytes;
  private List<ColumnDecryptionSetup> columnKeyList;
  private boolean processed;


  public FileDecryptionProperties() {
    this.keyRetriever = null;
    processed = false;
  }
  
  /**
   * Set an explicit footer key. If applied on a file that contains footer key metadata - 
   * the metadata will be ignored, the footer will be decrypted with this key.
   * @param footerKey Key length must be either 16, 24 or 32 bytes.
   * @throws IOException 
   */
  public void setFooterKey(byte[] footerKey) throws IOException {
    if (processed) throw new IOException("Properties already processed");
    if (null == footerKey) {
      throw new IOException("Setting null key");
    }
    this.footerKeyBytes = footerKey;
    if (! (footerKeyBytes.length == 16 || footerKeyBytes.length == 24 || footerKeyBytes.length == 32)) {
      throw new IOException("Wrong key length " + footerKeyBytes.length);
    }
  }


  /**
   * Convenience method for regular (not nested) columns.
   * @param columnName
   * @param columnKey
   * @throws IOException
   */
  public void setColumnKey(String columnName, byte[] columnKey) throws IOException {
    setColumnKey(new String[] {columnName}, columnKey);
  }

  /**
   * Set an explicit column key. If applied on a file that contains key metadata for this column - 
   * the metadata will be ignored, the column will be decrypted with this key.
   * @param columnPath
   * @param columnKey Key length must be either 16, 24 or 32 bytes.
   * @throws IOException 
   */
  public void setColumnKey(String[] columnPath, byte[] columnKey) throws IOException {
    if (processed) throw new IOException("Properties already processed");
    if (null == columnKey) throw new IOException("Decryption: null column key");
    if (! (columnKey.length == 16 || columnKey.length == 24 || columnKey.length == 32)) {
      throw new IOException("Wrong key length " + columnKey.length);
    }
    // TODO compare to footer key?
    // TODO if set for this column, throw an exception? or allow to replace
    if (null == columnKeyList) columnKeyList = new ArrayList<ColumnDecryptionSetup>();
    ColumnDecryptionSetup cmd = new ColumnDecryptionSetup(true, columnPath);
    cmd.setEncryptionKey(columnKey);
    columnKeyList.add(cmd);
  }
  
  /**
   * Set a key retriever callback. Its also possible to
   * set explicit footer or column keys on this property object. Upon file decryption, 
   * availability of explicit keys is checked before invocation of the retriever callback.
   * @param keyRetriever
   */
  public void setKeyRetriever(DecryptionKeyRetriever keyRetriever) {
    this.keyRetriever = keyRetriever;
    this.footerKeyBytes = null;
    processed = false;
  }
  
  /**
   * Set the AES-GCM additional authenticated data (AAD).
   * 
   * @param aad
   * @throws IOException 
   */
  public void setAAD(byte[] aad) throws IOException {
    if (processed) throw new IOException("Properties already processed");
    // TODO if set, throw an exception? or allow to replace
    aadBytes = aad;
  }
  
  /**
   * Set an AAD retrieval callback.
   * @param aadRetriever
   * @throws IOException
   */
  public void setAadRetriever(AADRetriever aadRetriever) throws IOException {
    if (processed) throw new IOException("Properties already processed");
    this.aadRetriever = aadRetriever;
  }
  

  byte[] getFooterKeyBytes() {
    processed = true;
    return footerKeyBytes;
  }

  DecryptionKeyRetriever getKeyRetriever() {
    processed = true;
    return keyRetriever;
  }

  byte[] getAAD() {
    processed = true;
    return aadBytes;
  }

  byte[] getColumnKey(String[] path) {
    processed = true;
    if (null == columnKeyList)  return null;
    for (ColumnDecryptionSetup col : columnKeyList) {
      if (Arrays.deepEquals(path, col.getPath())) {
        return col.getKeyBytes();
      }
    } 
    return null;
  }

  AADRetriever getAadRetriever() {
    processed = true;
    return aadRetriever;
  }
}
