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
import java.util.Arrays;
import java.util.List;

import org.apache.parquet.bytes.BytesUtils;
import org.apache.parquet.format.EncryptionAlgorithm;

public class FileEncryptionProperties {
  
  private final EncryptionAlgorithm algorithm;
  private final byte[] footerKeyBytes;
  private final byte[] footerKeyMetadata;
  
  private byte[] aadBytes;
  private List<ColumnEncryptionProperties> columnList;
  private boolean encryptTheRest;
  //Uniform encryption means footer and all columns are encrypted, with same key
  private boolean uniformEncryption;
  private boolean processed;
  
  /**
   * Constructor with a custom key metadata.
   * 
   * @param cipher 
   * @param keyBytes Encryption key for file footer and some (or all) columns. 
   * Key length must be either 16, 24 or 32 bytes.
   * If null, footer won't be encrypted.
   * @param keyMetadata Key metadata, to be written in a file for key retrieval upon decryption. Can be null.
   * Maximal length is 256 bytes.
   * @throws IOException 
   */
  public FileEncryptionProperties(ParquetCipher cipher, byte[] keyBytes, byte[] keyMetadata) throws IOException {
    if (null != keyBytes) {
      if (! (keyBytes.length == 16 || keyBytes.length == 24 || keyBytes.length == 32)) {
        throw new IOException("Wrong key length " + keyBytes.length);
      }
      uniformEncryption = true;
    }
    else {
      if (null != keyMetadata) {
        throw new IOException("Setting metadata for null footer key");
      }
      uniformEncryption = false;
    }
    if ((null != keyMetadata) && (keyMetadata.length > 256)) { // TODO 
      throw new IOException("Footer key meta data is too long: " + keyMetadata.length);
    }
    
    footerKeyBytes = keyBytes;
    footerKeyMetadata = keyMetadata;
    algorithm = cipher.getEncryptionAlgorithm();
    processed = false;
  }
  
  /**
   * Constructor with a 4-byte key metadata derived from an integer key ID.
   * 
   * @param keyBytes 
   * @param keyId Key id - will be converted to a 4-byte little endian metadata and written in a file for key retrieval upon decryption.
   * @throws IOException 
   */
  public FileEncryptionProperties(ParquetCipher algorithm, byte[] keyBytes, int keyId) throws IOException {
    this(algorithm, keyBytes, BytesUtils.intToBytes(keyId));
  }
  
  /**
   * Set column encryption properties. 
   * The list doesn't have to include all columns in a file. If encryptTheRest is true, the rest of the columns (not in the list)
   * will be encrypted with the file footer key. If encryptTheRest is false, the rest of the columns will be left unencrypted.
   * @param columnList
   * @param encryptTheRest  
   * @throws IOException 
   */
  public void setColumnProperties(List<ColumnEncryptionProperties> columnList, boolean encryptTheRest) throws IOException {
    if (processed) throw new IOException("Setup already processed");
    // TODO if set, throw an exception? or allow to replace
    uniformEncryption = false;
    this.encryptTheRest = encryptTheRest;
    this.columnList = columnList;
    if (null == footerKeyBytes) {
      if (encryptTheRest) throw new IOException("Encrypt the rest with null footer key");
      boolean all_are_unencrypted = true;
      for (ColumnEncryptionProperties cmd : columnList) {
        if (cmd.isEncrypted()) {
          if (null == cmd.getKeyBytes()) {
            throw new IOException("Encrypt column with null footer key");
          }
          all_are_unencrypted = false;
        }
      }
      if (all_are_unencrypted) throw new IOException("Footer and all columns unencrypted");
    }
  }
  
  /**
   * Set the AES-GCM additional authenticated data (AAD).
   * 
   * @param aad
   * @param aadMetadata Maximal length is 256 bytes.
   * @throws IOException 
   */
  public void setAAD(byte[] aad, byte[] aadMetadata) throws IOException {
    if (processed) throw new IOException("Setup already processed");
    if (null == aad) throw new IOException("Null AAD");
    // TODO if set, throw an exception? or allow to replace
    aadBytes = aad;
    if (null != aadMetadata) {
      if (aadMetadata.length > 256) throw new IOException("AAD metadata is too long: " + aadMetadata.length); //TODO
      if (algorithm.isSetAES_GCM_V1()) {
        algorithm.getAES_GCM_V1().setAad_metadata(aadMetadata);
      }
      else {
        algorithm.getAES_GCM_CTR_V1().setAad_metadata(aadMetadata);
      }
    }
  }
  
  EncryptionAlgorithm getAlgorithm() {
    processed = true;
    return algorithm;
  }

  byte[] getFooterKeyBytes() {
    processed = true;
    return footerKeyBytes;
  }

  byte[] getFooterKeyMetadata() {
    processed = true;
    return footerKeyMetadata;
  }

  boolean isUniformEncryption() {
    processed = true;
    return uniformEncryption;
  }

  ColumnEncryptionProperties getColumnMetadata(String[] columnPath) {
    processed = true;
    boolean in_list = false;
    ColumnEncryptionProperties cmd = null;
    for (ColumnEncryptionProperties col : columnList) {
      if (Arrays.deepEquals(columnPath, col.getPath())) {
        in_list = true;
        cmd = col;
        break;
      }
    }
    if (in_list) {
      return cmd;
    }
    else {
      return new ColumnEncryptionProperties(encryptTheRest, columnPath);
    }
  }

  byte[] getAAD() {
    processed = true;
    return aadBytes;
  }

  void checkUp() throws IOException {
    if (null == footerKeyBytes && null == columnList) {
      throw new IOException("Null footer key and column keys");
    }
    
  }
}
