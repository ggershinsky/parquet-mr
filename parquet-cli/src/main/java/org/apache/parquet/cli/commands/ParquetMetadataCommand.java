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

package org.apache.parquet.cli.commands;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import org.apache.parquet.cli.BaseCommand;
import org.apache.commons.lang.StringUtils;
import org.apache.parquet.column.ColumnDescriptor;
import org.apache.parquet.column.Encoding;
import org.apache.parquet.column.EncodingStats;
import org.apache.parquet.column.statistics.Statistics;
import org.apache.parquet.crypto.DecryptionSetup;
import org.apache.parquet.crypto.IntegerKeyIdRetriever;
import org.apache.parquet.crypto.ParquetEncryptionFactory;
import org.apache.parquet.crypto.ParquetFileDecryptor;
import org.apache.parquet.format.converter.ParquetMetadataConverter;
import org.apache.parquet.hadoop.ParquetFileReader;
import org.apache.parquet.hadoop.metadata.BlockMetaData;
import org.apache.parquet.hadoop.metadata.ColumnChunkMetaData;
import org.apache.parquet.hadoop.metadata.CompressionCodecName;
import org.apache.parquet.hadoop.metadata.ParquetMetadata;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.PrimitiveType;
import org.slf4j.Logger;
import javax.annotation.Nullable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.parquet.cli.Util.encodingStatsAsString;
import static org.apache.parquet.cli.Util.encodingsAsString;
import static org.apache.parquet.cli.Util.humanReadable;
import static org.apache.parquet.cli.Util.minMaxAsString;
import static org.apache.parquet.cli.Util.primitive;
import static org.apache.parquet.cli.Util.shortCodec;

@Parameters(commandDescription="Print a Parquet file's metadata")
public class ParquetMetadataCommand extends BaseCommand {

  public ParquetMetadataCommand(Logger console) {
    super(console);
  }

  @Parameter(description = "<parquet path>")
  List<String> targets;
  
  @Parameter(names={"-e", "--encrypted-file"},
      description="Cat an encrypted Parquet file")
  boolean encrypt = false;
  
  @Parameter(names={"--key"},
      description="Encryption key (base64 string)")
  String encodedKey;


  @Override
  @SuppressWarnings("unchecked")
  public int run() throws IOException {
    Preconditions.checkArgument(targets != null && targets.size() >= 1,
        "A Parquet file is required.");
    Preconditions.checkArgument(targets.size() == 1,
        "Cannot process multiple Parquet files.");

    String source = targets.get(0);
    
    ParquetFileDecryptor fileDecryptor = null;
    if (encrypt) {
      byte[] keyBytes;
      if (null == encodedKey) {
        keyBytes = new byte[16];
        for (byte i=0; i < 16; i++) {keyBytes[i] = i;}
        String sampleKey = Base64.getEncoder().encodeToString(keyBytes);
        console.info("Decrypting with a sample key: " +sampleKey);
      }
      else {
        keyBytes = Base64.getDecoder().decode(encodedKey);
      }
      
      IntegerKeyIdRetriever kr = new IntegerKeyIdRetriever();
      kr.putKey(12, keyBytes);
      
      byte[] colKeyBytes = new byte[16]; 
      for (byte i=0; i < 16; i++) {colKeyBytes[i] = (byte) (i%3);}
      //kr.putKey(15, colKeyBytes);
      
      DecryptionSetup dSetup = new DecryptionSetup(kr);
      
      byte[] aad = source.getBytes(StandardCharsets.UTF_8);
      console.info("AAD: "+source+". Len: "+aad.length);
      dSetup.setAAD(aad); 
 
      //fileDecryptor = ParquetEncryptionFactory.createFileDecryptor(keyBytes);
      fileDecryptor = ParquetEncryptionFactory.createFileDecryptor(dSetup);
    }
    
    ParquetMetadata footer = ParquetFileReader.readFooter(
        getConf(), qualifiedPath(source), ParquetMetadataConverter.NO_FILTER, fileDecryptor);

    console.info("\nFile path:  {}", source);
    console.info("Created by: {}", footer.getFileMetaData().getCreatedBy());

    Map<String, String> kv = footer.getFileMetaData().getKeyValueMetaData();
    if (kv != null && !kv.isEmpty()) {
      console.info("Properties:");
      String format = "  %" + maxSize(kv.keySet()) + "s: %s";
      for (Map.Entry<String, String> entry : kv.entrySet()) {
        console.info(String.format(format, entry.getKey(), entry.getValue()));
      }
    } else {
      console.info("Properties: (none)");
    }

    MessageType schema = footer.getFileMetaData().getSchema();
    console.info("Schema:\n{}", schema);

    List<BlockMetaData> rowGroups = footer.getBlocks();
    for (int index = 0, n = rowGroups.size(); index < n; index += 1) {
      printRowGroup(console, index, rowGroups.get(index), schema);
    }

    console.info("");

    return 0;
  }

  @Override
  public List<String> getExamples() {
    return Lists.newArrayList(
    );
  }

  private int maxSize(Iterable<String> strings) {
    int size = 0;
    for (String s : strings) {
      size = Math.max(size, s.length());
    }
    return size;
  }

  private void printRowGroup(Logger console, int index, BlockMetaData rowGroup, MessageType schema) {
    
    console.info("");
      
    long start = -1;
    try {
      start = rowGroup.getStartingPos();
    }
    catch (RuntimeException e) { // TODO
      console.info(String.format("First column is hidden, can't calculate starting position", index));
    }
    long rowCount = rowGroup.getRowCount();
    long compressedSize = -1;
    try {
      compressedSize = rowGroup.getCompressedSize();
    }
    catch (RuntimeException e) { //TODO
      console.info(String.format("Hidden column(s), can't calculate total compressed size", index));
    }
    long uncompressedSize = rowGroup.getTotalByteSize();
    String filePath = rowGroup.getPath();

    console.info(String.format("Row group %d:  start: %d count: %d. \n  Compressed  :  %s records  total: %s. \n  Uncompressed:  %s records  total: %s%s\n%s",
        index, start, rowCount,
        humanReadable(((float) compressedSize) / rowCount),
        humanReadable(compressedSize),
        humanReadable(((float) uncompressedSize) / rowCount),
        humanReadable(uncompressedSize),
        filePath != null ? " path: " + filePath : "",
        StringUtils.leftPad("", 80, '-')));
        

    int size = maxSize(Iterables.transform(rowGroup.getColumns(),
        new Function<ColumnChunkMetaData, String>() {
          @Override
          public String apply(@Nullable ColumnChunkMetaData input) {
            return input == null ? "" : input.getPath().toDotString();
          }
        }));

    console.info(String.format("%-" + size + "s  %-9s %-9s %-9s %-10s %-7s %s",
        "", "type", "encodings", "count", "avg size", "nulls", "min / max"));
    for (ColumnChunkMetaData column : rowGroup.getColumns()) {
      printColumnChunk(console, size, column, schema);
    }
  }

  private void printColumnChunk(Logger console, int width, ColumnChunkMetaData column, MessageType schema) {
    String name = column.getPath().toDotString();
    
    if (column.isHiddenColumn()) {
      console.info(String.format("%-" + (width+1) + "s %-9s %s %-7s %-9s %-10s %-7s %s", 
          name, "HIDDEN", "-", "-", "-", "-", "-", "\"-\" / \"-\""));
      return;
    }
    
    String[] path = column.getPath().toArray();
    PrimitiveType type = primitive(schema, path);
    Preconditions.checkNotNull(type);

    ColumnDescriptor desc = schema.getColumnDescription(path);
    long size = column.getTotalSize();
    long count = column.getValueCount();
    float perValue = ((float) size) / count;
    CompressionCodecName codec = column.getCodec();
    Set<Encoding> encodings = column.getEncodings();
    EncodingStats encodingStats = column.getEncodingStats();
    String encodingSummary = encodingStats == null ?
        encodingsAsString(encodings, desc) :
        encodingStatsAsString(encodingStats);
    Statistics stats = column.getStatistics();

    PrimitiveType.PrimitiveTypeName typeName = type.getPrimitiveTypeName();
    if (typeName == PrimitiveType.PrimitiveTypeName.FIXED_LEN_BYTE_ARRAY) {
      console.info(String.format("%-" + width + "s  FIXED[%d] %s %-7s %-9d %-8s %-7s %s",
          name, type.getTypeLength(), shortCodec(codec), encodingSummary, count,
          humanReadable(perValue), stats == null || !stats.isNumNullsSet() ? "" : String.valueOf(stats.getNumNulls()),
          minMaxAsString(stats, type.getOriginalType())));
    } else {
      console.info(String.format("%-" + width + "s  %-9s %s %-7s %-9d %-10s %-7s %s",
          name, typeName, shortCodec(codec), encodingSummary, count, humanReadable(perValue),
          stats == null || !stats.isNumNullsSet() ? "" : String.valueOf(stats.getNumNulls()),
          minMaxAsString(stats, type.getOriginalType())));
    }
  }
}
