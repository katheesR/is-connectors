/*
 *Copyright (c) 2005-2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */
package org.wso2.carbon.linkedin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.net.HttpURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.ui.CarbonUIUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAuthzResponse;
import org.apache.amber.oauth2.client.response.OAuthClientResponse;
import org.apache.amber.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;

public class LinkedInOAuth2Authenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4154255583070524018L;

    private static Log log = LogFactory.getLog(LinkedInOAuth2Authenticator.class);

    /**
     * @return
     */
    protected String getAuthorizationServerEndpoint(
            Map<String, String> authenticatorProperties) {

        return LinkedInOAuth2AuthenticationConstant.LINKEDIN_OAUTH_ENDPOINT;
    }

    /**
     * @return
     */
    protected String getTokenEndpoint(
            Map<String, String> authenticatorProperties) {

        return LinkedInOAuth2AuthenticationConstant.LINKEDIN_TOKEN_ENDPOINT;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isTraceEnabled()) {
            log.trace("Inside LinkedInOAuth2Authenticator.canHandle()");
        }

        // Check common auth got an OIDC response
        if (request.getParameter(LinkedInOAuth2AuthenticationConstant.OAUTH2_GRANT_TYPE_CODE) != null
                && request.getParameter(LinkedInOAuth2AuthenticationConstant.OAUTH2_PARAM_STATE) != null
                && LinkedInOAuth2AuthenticationConstant.LINKEDIN_LOGIN_TYPE.equals(getLoginType(request))) {
            return true;
        }

        return false;
    }

    /**
     * This is override because of query string values hard coded and input
     * values validations are not required.
     *
     * @param request the initial authentication request
     * @param response the response
     * @param context the application context
     * @throws AuthenticationFailedException
     */

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String clientId = authenticatorProperties
                        .get(LinkedInOAuth2AuthenticationConstant.CLIENT_ID);
                String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);

                if (authorizationEP == null) {
                    authorizationEP = authenticatorProperties
                            .get(LinkedInOAuth2AuthenticationConstant.OAUTH2_AUTHZ_URL);
                }

                String callbackUrl = getCallbackUrl(authenticatorProperties);

                if (callbackUrl == null) {
                    callbackUrl = CarbonUIUtil.getAdminConsoleURL(request);
                    callbackUrl = callbackUrl.replace("commonauth/carbon/",
                            "commonauth");
                }

                String state = context.getContextIdentifier() + ","
                        + LinkedInOAuth2AuthenticationConstant.LINKEDIN_LOGIN_TYPE;

                state = getState(state, authenticatorProperties);

                OAuthClientRequest authzRequest;

                // This is the query string need to send getting email and
                // profile
                String queryString = LinkedInOAuth2AuthenticationConstant.QUERY_STRING;

                authzRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callbackUrl)
                        .setResponseType(
                                LinkedInOAuth2AuthenticationConstant.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state).buildQueryMessage();

                String loginPage = authzRequest.getLocationUri();
                String domain = request.getParameter("domain");

                if (domain != null) {
                    loginPage = loginPage + "&fidp=" + domain;
                }

                if (queryString != null) {
                    if (!queryString.startsWith("&")) {
                        loginPage = loginPage + "&" + queryString;
                    } else {
                        loginPage = loginPage + queryString;
                    }
                }
                response.sendRedirect(loginPage);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException(
                        "Error while retrieving properties. Authenticator Properties cannot be null");
            }
        } catch (IOException e) {
            log.error("Exception while sending to the login page", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            log.error("Exception while building authorization code request", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return;
    }

    /**
     * @return
     */
    protected String getScope(String scope,
                              Map<String, String> authenticatorProperties) {

        return LinkedInOAuth2AuthenticationConstant.OAUTH_OIDC_SCOPE;
    }

    /**
     * @param token
     * @return
     */
    protected String getAuthenticateUser(OAuthClientResponse token) {
        return token.getParam(LinkedInOAuth2AuthenticationConstant.Claim.EMAIL);
    }

    /**
     * @param claimMap
     * @return
     */

    protected Map<ClaimMapping, String> getSubjectAttributes(
            Map<String, Object> claimMap) {

        Map<ClaimMapping, String> claims = new HashMap<ClaimMapping, String>();

            if (claimMap != null) {
                for (Map.Entry<String, Object> entry : claimMap.entrySet()) {
                    claims.put(ClaimMapping.build(entry.getKey(),
                            entry.getKey(), null, false), entry.getValue()
                            .toString());
                    if (log.isDebugEnabled()) {
                        log.debug("Adding claim from end-point data mapping : "
                                + entry.getKey() + " <> " + " : "
                                + entry.getValue());
                    }

                }
            }

        return claims;
    }

    protected Map<String, Object> getUserClaims(OAuthClientResponse token){
        try {
            String json = sendRequest(
                    LinkedInOAuth2AuthenticationConstant.LINKEDIN_USERINFO_ENDPOINT,
                    token.getParam(LinkedInOAuth2AuthenticationConstant.ACCESS_TOKEN));

            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);

                return jsonObject;
        } catch (Exception e) {
            log.error(e);
        }
        return new HashMap<String, Object>();

    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(LinkedInOAuth2AuthenticationConstant.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter LinkedIn IDP client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(LinkedInOAuth2AuthenticationConstant.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter LinkedIn IDP client secret value");
        configProperties.add(clientSecret);

        Property callBackURL = new Property();
        callBackURL.setName(LinkedInOAuth2AuthenticationConstant.OAUTH2_CALLBACK_URL);
        callBackURL.setDisplayName("Callback URL");
        callBackURL.setRequired(true);
        callBackURL.setDescription("Enter LinkedIn IDP redirect URL value");
        configProperties.add(callBackURL);

        return configProperties;
    }

    /**
     * this method are overridden for extra claim request to linkedin end-point
     *
     * @param request
     * @param response
     * @param context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {

            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();
            String clientId = authenticatorProperties
                    .get(LinkedInOAuth2AuthenticationConstant.CLIENT_ID);
            String clientSecret = authenticatorProperties
                    .get(LinkedInOAuth2AuthenticationConstant.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);

            if (tokenEndPoint == null) {
                tokenEndPoint = authenticatorProperties
                        .get(LinkedInOAuth2AuthenticationConstant.OAUTH2_TOKEN_URL);
            }

            String callbackurl = getCallbackUrl(authenticatorProperties);

            if (callbackurl == null) {
                callbackurl = CarbonUIUtil.getAdminConsoleURL(request);
                callbackurl = callbackurl.replace("commonauth/carbon/",
                        "commonauth");
            }

            @SuppressWarnings({"unchecked"})
            Map<String, String> paramValueMap = (Map<String, String>) context
                    .getProperty("oidc:param.map");

            if (paramValueMap != null
                    && paramValueMap.containsKey("redirect_uri")) {
                callbackurl = paramValueMap.get("redirect_uri");
            }

            OAuthAuthzResponse authzResponse = OAuthAuthzResponse
                    .oauthCodeAuthzResponse(request);
            String code = authzResponse.getCode();

            OAuthClientRequest accessRequest;
            try {
                accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setClientId(clientId).setClientSecret(clientSecret)
                        .setRedirectURI(callbackurl).setCode(code)
                        .buildBodyMessage();

            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Exception while building request for request access token",
                            e);
                }
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
            // create OAuth client that uses custom http client under the hood
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = null;
            try {
                oAuthResponse = oAuthClient.accessToken(accessRequest);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Exception while requesting access token", e);
                }
                throw new AuthenticationFailedException(e.getMessage(), e);
            }

            String accessToken = oAuthResponse
                    .getParam(LinkedInOAuth2AuthenticationConstant.ACCESS_TOKEN);
            if (accessToken != null) {

                Map<String, Object> userClaims = getUserClaims(oAuthResponse);
                if (userClaims != null && ! userClaims.isEmpty()) {
                    context.setSubjectAttributes(getSubjectAttributes(userClaims));
                    context.setSubject(userClaims.get(LinkedInOAuth2AuthenticationConstant.LINKEDIN_USER_ID).toString());
                }
                else {
                    throw new AuthenticationFailedException("Selected user profile found");
                }
            } else {
                throw new AuthenticationFailedException("Authentication Failed");
            }


        } catch (OAuthProblemException e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    public String getFriendlyName() {
        return LinkedInOAuth2AuthenticationConstant.LINKEDIN_CONNECTOR_FRIENDLY_NAME;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        if (log.isTraceEnabled()) {
            log.trace("Inside LinkedinOAuth2Authenticator.getContextIdentifier()");
        }
        String state = request.getParameter(LinkedInOAuth2AuthenticationConstant.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    @Override
    public String getName() {
        return LinkedInOAuth2AuthenticationConstant.LINKEDIN_CONNECTOR_NAME;
    }

    /**
     * extra request sending to linkedin userinfo end-point
     *
     * @param url
     * @param accessToken
     * @return
     * @throws IOException
     */
    private String sendRequest(String url, String accessToken)
            throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("claim url: " + url + " <> accessToken : " + accessToken);
        }
        URL obj = new URL(url + "&"+LinkedInOAuth2AuthenticationConstant.LINKEDIN_OAUTH2_ACCESS_TOKEN_PARAMETER+"=" + accessToken);

        HttpURLConnection urlConnection = (HttpURLConnection) obj
                .openConnection();

        urlConnection.setRequestMethod("GET");
        BufferedReader in = new BufferedReader(new InputStreamReader(
                urlConnection.getInputStream()));
        StringBuilder b = new StringBuilder();
        String inputLine = in.readLine();
        while (inputLine != null) {
            b.append(inputLine).append("\n");
            inputLine = in.readLine();
        }
        in.close();

        if (log.isDebugEnabled()) {
            log.debug("response: " + b.toString());
        }
        return b.toString();
    }

    private String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(LinkedInOAuth2AuthenticationConstant.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    /**
     *
     * @return
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {
        return null;
    }

    /**
     *
     * @param state
     * @return
     */
    protected String getState(String state, Map<String, String> authenticatorProperties) {
        return state;
    }
}
