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

public class LinkedInOAuth2AuthenticationConstant {
	

    public static final String LINKEDIN_OAUTH_ENDPOINT = "https://www.linkedin.com/uas/oauth2/authorization";
    public static final String LINKEDIN_TOKEN_ENDPOINT = "https://www.linkedin.com/uas/oauth2/accessToken";
    public static final String LINKEDIN_USERINFO_ENDPOINT = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,industry,headline,email-address)?format=json";
    public static final String LINKEDIN_CONNECTOR_FRIENDLY_NAME = "LinkedIn ";
    public static final String LINKEDIN_CONNECTOR_NAME = "LinkedInOauth2OpenIDAuthenticator";
    public static final String QUERY_STRING = "scope=r_basicprofile%20r_emailaddress%20w_share";
    public static final String LINKEDIN_USER_ID = "id";
    public static final String LINKEDIN_OAUTH2_ACCESS_TOKEN_PARAMETER = "oauth2_access_token";

    public static final String LINKEDIN_LOGIN_TYPE = "linkedin";
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String OAUTH_OIDC_SCOPE = "openid";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String ID_TOKEN = "id_token";
    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String OAUTH2_AUTHZ_URL = "OAuth2AuthUrl";
    public static final String OAUTH2_TOKEN_URL = "OAUTH2TokenUrl";
    public static final String OAUTH2_CALLBACK_URL = "OAuth2CallbackUrl";

    public class Claim  {
        public static final String SUB = "sub";
        public static final String NAME = "name";
        public static final String GIVEN_NAME = "given_name";
        public static final String FAMILY_NAME = "family_name";
        public static final String MIDDLE_NAME = "middle_name";
        public static final String NICK_NAME = "nickname";
        public static final String PREFERED_USERNAME = "preferred_username";
        public static final String PROFILE = "profile";
        public static final String PICTURE = "picture";
        public static final String WEBSITE = "website";
        public static final String EMAIL = "email";
    }
}
