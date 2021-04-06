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

package org.apache.ranger.services.hive;

import static org.junit.Assert.*;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import org.apache.commons.collections.MapUtils;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveResourceACLs;
import org.apache.ranger.authorization.hive.authorizer.RangerHivePolicyProvider;
import org.apache.ranger.authorization.hive.authorizer.RangerHiveResource;
import org.apache.ranger.plugin.policyengine.RangerAccessResource;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.apache.ranger.plugin.util.ServicePolicies;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class HiveACLProviderTest {
	private static Gson gsonBuilder;
	private static RangerBasePlugin plugin;
	private static RangerHivePolicyProvider policyProvider;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		gsonBuilder = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z")
				.setPrettyPrinting()
				.registerTypeAdapter(RangerAccessResource.class, new RangerResourceDeserializer())
				.create();

		plugin = new RangerBasePlugin("hive", "HiveACLProviderTest");
		RangerBasePlugin.getServicePluginMap().put("hivedev", plugin);
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testResourceMatcher_default() throws Exception {
		String[] tests = { "/aclprovider/test_aclprovider_default.json" };

		runTestsFromResourceFiles(tests);
	}

	private void runTestsFromResourceFiles(String[] resourceNames) throws Exception {
		for(String resourceName : resourceNames) {
			InputStream       inStream = this.getClass().getResourceAsStream(resourceName);
			InputStreamReader reader   = new InputStreamReader(inStream);

			runTests(reader, resourceName);
		}
	}

	private void runTests(InputStreamReader reader, String testName) throws Exception {
		HiveACLProviderTests testCases = gsonBuilder.fromJson(reader, HiveACLProviderTests.class);

		assertTrue("invalid input: " + testName, testCases != null && testCases.testCases != null);

		for(HiveACLProviderTests.TestCase testCase : testCases.testCases) {
			plugin.setPolicies(testCase.servicePolicies);
			policyProvider = new RangerHivePolicyProvider(plugin);

			for(HiveACLProviderTests.TestCase.OneTest oneTest : testCase.tests) {
				if(oneTest == null) {
					continue;
				}
				HiveResourceACLs acls = policyProvider.getResourceACLs(oneTest.resource);
				boolean userACLsMatched = true, groupACLsMatched = true;

				if (MapUtils.isNotEmpty(acls.getUserPermissions()) && MapUtils.isNotEmpty(oneTest.userPermissions)) {
					for (Map.Entry<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> entry :
							acls.getUserPermissions().entrySet()) {
						String userName = entry.getKey();
						Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult> expected = oneTest.userPermissions.get(userName);
						if (MapUtils.isNotEmpty(entry.getValue()) && MapUtils.isNotEmpty(expected)) {
							// Compare
							for (Map.Entry<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult> privilege : entry.getValue().entrySet())
							{
								HiveResourceACLs.AccessResult expectedResult = expected.get(privilege.getKey());
								if (expectedResult == null) {
									if (privilege.getValue().equals(HiveResourceACLs.AccessResult.CONDITIONAL_ALLOWED)) {
										continue;
									} else {
										userACLsMatched = false;
										break;
									}
								} else if (!expectedResult.equals(privilege.getValue())) {
									userACLsMatched = false;
									break;
								}
							}
						} else if (!(MapUtils.isEmpty(entry.getValue()) && MapUtils.isEmpty(expected))){
							userACLsMatched = false;
							break;
						}
						if (!userACLsMatched) {
							break;
						}
					}
				} else if (!(MapUtils.isEmpty(acls.getUserPermissions()) && MapUtils.isEmpty(oneTest.userPermissions))) {
					userACLsMatched = false;
				}

				if (MapUtils.isNotEmpty(acls.getGroupPermissions()) && MapUtils.isNotEmpty(oneTest.groupPermissions)) {
					for (Map.Entry<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> entry :
							acls.getGroupPermissions().entrySet()) {
						String groupName = entry.getKey();
						Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult> expected = oneTest.groupPermissions.get(groupName);
						if (MapUtils.isNotEmpty(entry.getValue()) && MapUtils.isNotEmpty(expected)) {
							// Compare
							for (Map.Entry<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult> privilege : entry.getValue().entrySet()) {
								HiveResourceACLs.AccessResult expectedResult = expected.get(privilege.getKey());
								if (expectedResult == null) {
									if (privilege.getValue().equals(HiveResourceACLs.AccessResult.CONDITIONAL_ALLOWED)) {
										continue;
									} else {
										groupACLsMatched = false;
										break;
									}
								} else if (!expectedResult.equals(privilege.getValue())) {
									groupACLsMatched = false;
									break;
								}
							}
						} else if (!(MapUtils.isEmpty(entry.getValue()) && MapUtils.isEmpty(expected))) {
							groupACLsMatched = false;
							break;
						}
						if (!groupACLsMatched) {
							break;
						}
					}
				} else if (!(MapUtils.isEmpty(acls.getGroupPermissions()) && MapUtils.isEmpty(oneTest.groupPermissions))) {
					groupACLsMatched = false;
				}

				assertTrue("getResourceACLs() failed! " + testCase.name + ":" + oneTest.name, userACLsMatched && groupACLsMatched);
			}
		}
	}

	static class HiveACLProviderTests {
		List<TestCase> testCases;

		class TestCase {
			String               name;
			ServicePolicies      servicePolicies;
			List<OneTest>        tests;

			class OneTest {
				String               name;
				RangerHiveResource   resource;
				Map<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> userPermissions;
				Map<String, Map<HiveResourceACLs.Privilege, HiveResourceACLs.AccessResult>> groupPermissions;
			}
		}
	}

	static class RangerResourceDeserializer implements JsonDeserializer<RangerAccessResource> {
		@Override
		public RangerAccessResource deserialize(JsonElement jsonObj, Type type,
		                                        JsonDeserializationContext context) throws JsonParseException {
			return gsonBuilder.fromJson(jsonObj, RangerHiveResource.class);
		}
	}
}

