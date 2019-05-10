/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.webfinger.builders;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.webfinger.WebFingerConstants;
import org.wso2.carbon.identity.webfinger.WebFingerEndpointException;
import org.wso2.carbon.identity.webfinger.WebFingerRequest;
import org.wso2.carbon.identity.webfinger.WebFingerResponse;

import java.net.URISyntaxException;

import static org.wso2.carbon.identity.discovery.DiscoveryUtil.isUseEntityIdAsIssuerInOidcDiscovery;

/**
 * Build the WebFingerResponse only with the OpenID Provider Issuer.
 * Add other information when needed.
 */
public class WebFingerOIDCResponseBuilder {

    private static Log log = LogFactory.getLog(WebFingerOIDCResponseBuilder.class);

    public WebFingerResponse buildWebFingerResponse(WebFingerRequest request) throws WebFingerEndpointException,
            ServerConfigurationException {

        WebFingerResponse response;
        String oidcIssuerLocation;
        try {
            oidcIssuerLocation = getOidcIssuerLocation(request.getTenant());
        } catch (URISyntaxException e) {
            throw new ServerConfigurationException("URI Syntax error while retrieving oidcIssuerLocation for tenant: " +
                    request.getTenant(), e);
        } catch (IdentityOAuth2Exception e) {
            throw new WebFingerEndpointException ("Error while retrieving oidcIssuerLocation for tenant: " +
                    request.getTenant());
        }
        response = new WebFingerResponse();
        response.setSubject(request.getResource());
        response.addLink(WebFingerConstants.OPENID_CONNETCT_ISSUER_REL, oidcIssuerLocation);
        return response;
    }

    /**
     * Method to get OIDC Issuer location
     * @param tenantDomain
     * @return OidcIssuerLocation
     * @throws IdentityOAuth2Exception
     * @throws URISyntaxException
     */
    private String getOidcIssuerLocation(String tenantDomain) throws IdentityOAuth2Exception, URISyntaxException {

        if (isUseEntityIdAsIssuerInOidcDiscovery()) {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving OIDC Issuer location value: " + OAuth2Util.getResidentIDPEntityID(tenantDomain) +
                        " of tenant: " + tenantDomain + " from the Resident IDP configs.");
            }
            return OAuth2Util.getResidentIDPEntityID(tenantDomain);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving OIDC Issuer location value: " +
                        OAuth2Util.OAuthURL.getOidcDiscoveryEPUrl(tenantDomain) + " of tenant: " + tenantDomain +
                        " from the values in identity.xml file.");
            }
            return OAuth2Util.OAuthURL.getOidcDiscoveryEPUrl(tenantDomain);
        }
    }
}
