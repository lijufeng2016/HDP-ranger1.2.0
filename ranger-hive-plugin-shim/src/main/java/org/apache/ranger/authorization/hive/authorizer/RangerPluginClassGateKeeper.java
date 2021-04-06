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

package org.apache.ranger.authorization.hive.authorizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.classloader.RangerPluginClassLoader;

public class RangerPluginClassGateKeeper {

    private static final Log LOG  = LogFactory.getLog(RangerPluginClassGateKeeper.class);

    private static final String   RANGER_PLUGIN_TYPE                      = "hive";

    private RangerPluginClassLoader rangerPluginClassLoader 			  = null;

    RangerPluginClassGateKeeper() {}

    protected void init() {
        try {
            rangerPluginClassLoader = RangerPluginClassLoader.getInstance(RANGER_PLUGIN_TYPE, this.getClass());
        } catch (Exception exception) {
            LOG.error("Error Enabling RangerHivePlugin", exception);
        }
    }
    protected void activatePluginClassLoader() {
        if(rangerPluginClassLoader != null) {
            rangerPluginClassLoader.activate();
        }
    }

    protected void deactivatePluginClassLoader() {
        if(rangerPluginClassLoader != null) {
            rangerPluginClassLoader.deactivate();
        }
    }
    protected ClassLoader getRangerPluginClassLoader() {
        return rangerPluginClassLoader;
    }

}
