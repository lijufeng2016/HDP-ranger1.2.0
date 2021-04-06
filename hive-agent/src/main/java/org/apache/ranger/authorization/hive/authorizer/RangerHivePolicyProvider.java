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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePolicyChangeListener;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePolicyProvider;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilegeObject;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveResourceACLs;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngine;
import org.apache.ranger.plugin.policyengine.RangerResourceACLs;
import org.apache.ranger.plugin.policyevaluator.RangerPolicyEvaluator;
import org.apache.ranger.plugin.service.RangerAuthContext;
import org.apache.ranger.plugin.service.RangerAuthContextListener;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.apache.ranger.plugin.util.RangerPerfTracer;

import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class RangerHivePolicyProvider implements HivePolicyProvider {
    private static final Log LOG = LogFactory.getLog(RangerHivePolicyProvider.class);

    private static final Log PERF_HIVEACLPROVIDER_REQUEST_LOG = RangerPerfTracer.getPerfLogger("hiveACLProvider.request");

	private static final RangerHiveAuthContextListener authContextListener = new RangerHiveAuthContextListener();

	private static volatile Set<String> hivePrivileges = null;

	private final RangerBasePlugin  rangerPlugin;
	private final RangerAuthContext authContext;

	public RangerHivePolicyProvider(@NotNull RangerBasePlugin hivePlugin) {
		if (hivePrivileges == null) {
			synchronized(RangerHivePolicyProvider.class) {
				if (hivePrivileges == null) {
					hivePrivileges = new HashSet<>();
					for (HiveResourceACLs.Privilege privilege : HiveResourceACLs.Privilege.values()) {
						hivePrivileges.add(privilege.name().toLowerCase());
					}
				}
			}

		}
		this.rangerPlugin = hivePlugin;
		authContext = hivePlugin.createRangerAuthContext();
	}

	@Override
    public HiveResourceACLs getResourceACLs(HivePrivilegeObject hiveObject) {

	    HiveResourceACLs ret;

	    RangerPerfTracer perf = null;

	    if (RangerPerfTracer.isPerfTraceEnabled(PERF_HIVEACLPROVIDER_REQUEST_LOG)) {
		    perf = RangerPerfTracer.getPerfTracer(PERF_HIVEACLPROVIDER_REQUEST_LOG, "RangerHivePolicyProvider.getResourceACLS()");
	    }
	    // Extract and build RangerHiveResource from inputObject
	    RangerHiveResource hiveResource = RangerHiveAuthorizer.createHiveResource(hiveObject);
	    ret = getResourceACLs(hiveResource);
	    RangerPerfTracer.log(perf);
		return ret;
    }

	@Override
	public void registerHivePolicyChangeListener(HivePolicyChangeListener listener) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("==> RangerHiveACLProviderFactory.registerACLProviderChangeListener()");
		}
		authContextListener.providerChangeListeners.add(listener);

		RangerHivePlugin hivePlugin = null;
		// Get hivePlugin and register for changes there
		if (rangerPlugin instanceof RangerHivePlugin) {
			hivePlugin = (RangerHivePlugin) rangerPlugin;
		}
		if (hivePlugin != null) {
			hivePlugin.registerAuthContextEventListener(authContextListener);
		} else {
			LOG.error("Hive Plugin is NULL!!!");
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("<== RangerHiveACLProviderFactory.registerACLProviderChangeListener()");
		}
	}

	static class RangerHiveAuthContextListener implements RangerAuthContextListener {
		Set<HivePolicyChangeListener> providerChangeListeners = new HashSet<>();

		public void contextChanged() {
			for (HivePolicyChangeListener eventListener : providerChangeListeners) {
				eventListener.notifyPolicyChange(null);
			}
		}
	}
	public RangerAuthContext getAuthContext() {
		return authContext;
	}

	public HiveResourceACLs getResourceACLs(RangerHiveResource hiveResource) {
	    HiveResourceACLs ret;

	    RangerAccessRequestImpl request = new RangerAccessRequestImpl(hiveResource, RangerPolicyEngine.ANY_ACCESS, null, null);

	    RangerResourceACLs acls = authContext.getResourceACLs(request);

	    if (LOG.isDebugEnabled()) {
	    	LOG.debug("HiveResource:[" + hiveResource.getAsString() + "], Computed ACLS:[" + acls + "]");
	    }

	    Map<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> userPermissions = convertRangerACLsToHiveACLs(acls.getUserACLs());
	    Map<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> groupPermissions = convertRangerACLsToHiveACLs(acls.getGroupACLs());

	    ret = new RangerHiveResourceACLs(userPermissions, groupPermissions);

	    return ret;
    }

    private Map<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> convertRangerACLsToHiveACLs(Map<String, Map<String, RangerResourceACLs.AccessResult>> rangerACLs) {

	    Map<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> ret = new HashMap<>();

	    if (MapUtils.isNotEmpty(rangerACLs)) {

		    for (Map.Entry<String, Map<String, RangerResourceACLs.AccessResult>> entry : rangerACLs.entrySet()) {

			    Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult> permissions = new HashMap<>();

			    ret.put(entry.getKey(), permissions);

			    for (Map.Entry<String, RangerResourceACLs.AccessResult> permission : entry.getValue().entrySet()) {

				    if (hivePrivileges.contains(permission.getKey())) {

					    HiveResourceACLs.Privilege privilege = HiveResourceACLs.Privilege.valueOf(StringUtils.upperCase(permission.getKey()));

					    HiveResourceACLs.AccessResult accessResult;

					    int rangerResultValue = permission.getValue().getResult();

					    if (rangerResultValue == RangerPolicyEvaluator.ACCESS_ALLOWED) {
						    accessResult = HiveResourceACLs.AccessResult.ALLOWED;
					    } else if (rangerResultValue == RangerPolicyEvaluator.ACCESS_DENIED) {
						    accessResult = HiveResourceACLs.AccessResult.NOT_ALLOWED;
					    } else if (rangerResultValue == RangerPolicyEvaluator.ACCESS_CONDITIONAL) {
						    accessResult = HiveResourceACLs.AccessResult.CONDITIONAL_ALLOWED;
					    } else {
						    // Should not get here
						    accessResult = HiveResourceACLs.AccessResult.NOT_ALLOWED;
					    }

					    permissions.put(privilege, accessResult);
				    }

			    }
		    }
	    }

	    return ret;
    }
}
