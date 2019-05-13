/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.application.authenticator.cognito;

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.when;

public class DefaultConfigTest {

    private CognitoOIDCAuthenticator cognitoOIDCAuthenticator;

    Map<String, String> authenticatorProperties = new HashMap<>();

    @Mock
    HttpServletRequest request;

    @Mock
    HttpServletResponse response;

    @Mock
    OAuthClientResponse clientResponse;

    @Mock
    AuthenticationContext context;

    @BeforeTest
    public void setUp() throws Exception {

        initMocks(this);
        cognitoOIDCAuthenticator = new CognitoOIDCAuthenticator();
        authenticatorProperties.put(CognitoOIDCAuthenticatorConstants.COGNITO_USER_POOL_DOMAIN, "user-pool");
        authenticatorProperties.put(CognitoOIDCAuthenticatorConstants.CLIENT_ID, "client-id");
        authenticatorProperties.put(CognitoOIDCAuthenticatorConstants.LOGOUT_REDIRECT_URL, "logout-redirect");
        authenticatorProperties.put(CognitoOIDCAuthenticatorConstants.ADDITIONAL_QUERY_PARAMS, "additional-param");

        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        Field configFilePathField = FileBasedConfigurationBuilder.class.getDeclaredField("configFilePath");
        configFilePathField.setAccessible(true);
        String path = classLoader.getResource("application-authentication-without-conf.xml").getPath();
        configFilePathField.set(null, path);
    }

    @Test
    public void testDefaultParameter() {

        String claimDialectURI = cognitoOIDCAuthenticator.getClaimDialectURI();
        Assert.assertEquals(claimDialectURI, "http://wso2.org/oidc/claim", "Claim uri didn't match");

        String endpoint = cognitoOIDCAuthenticator.getAuthorizationServerEndpoint(authenticatorProperties);
        Assert.assertEquals(endpoint, "user-pool/oauth2/authorize", "authorize endpoint didn't match");

        endpoint = cognitoOIDCAuthenticator.getTokenEndpoint(authenticatorProperties);
        Assert.assertEquals(endpoint, "user-pool/oauth2/token", "token endpoint didn't match");

        endpoint = cognitoOIDCAuthenticator.getUserInfoEndpoint(clientResponse, authenticatorProperties);
        Assert.assertEquals(endpoint, "user-pool/oauth2/userInfo", "user info endpoint didn't match");
    }

    @Test
    public void testInitiateLogoutRequest() throws Exception {

        when(context.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(context.getContextIdentifier()).thenReturn("context-identifier");
        cognitoOIDCAuthenticator.initiateLogoutRequest(request, response, context);
        verify(response).addCookie(anyObject());
    }
}
