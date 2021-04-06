/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.examples.customudf;

import org.apache.hadoop.hive.ql.exec.Description;
import org.apache.hadoop.hive.ql.exec.UDF;
import org.apache.hadoop.io.Text;

@Description(
        name = "toupper",
        value = "_FUNC_(str) - Converts a string to uppercase",
        extended = "Example:\n" +
                "  > SELECT toupper(author_name) FROM authors a;\n" +
                "  CONAN DOYLE"
)
public class ToUpper extends UDF {

    public Text evaluate(Text s) {
        Text to_value = new Text("");
        if (s != null) {
            try {
                to_value.set(s.toString().toUpperCase());
            } catch (Exception e) { // Should never happen

                to_value = new Text(s);
            }
        }
        return to_value;
    }
}
