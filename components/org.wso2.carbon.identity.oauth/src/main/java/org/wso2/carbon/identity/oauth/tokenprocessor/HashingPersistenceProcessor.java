/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.apache.commons.codec.digest.DigestUtils;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * An implementation of <Code>TokenPersistenceProcessor</Code>
 * which is used when storing hashed tokens.
 */
public class HashingPersistenceProcessor implements TokenPersistenceProcessor{

    @Override
    public String getProcessedClientId(String clientId) throws IdentityOAuth2Exception {
        return null;
    }

    @Override
    public String getPreprocessedClientId(String processedClientId) throws IdentityOAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedClientSecret(String clientSecret) throws IdentityOAuth2Exception {
        return hash(clientSecret);
    }

    @Override
    public String getPreprocessedClientSecret(String processedClientSecret) throws IdentityOAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedAuthzCode(String authzCode) throws IdentityOAuth2Exception {
        return hash(authzCode);
    }

    @Override
    public String getPreprocessedAuthzCode(String processedAuthzCode) throws IdentityOAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedAccessTokenIdentifier(String accessTokenIdentifier) throws IdentityOAuth2Exception {

        return hash(accessTokenIdentifier);
    }

    @Override
    public String getPreprocessedAccessTokenIdentifier(String processedAccessTokenIdentifier)
            throws IdentityOAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedRefreshToken(String refreshToken) throws IdentityOAuth2Exception {
        return hash(refreshToken);
    }

    @Override
    public String getPreprocessedRefreshToken(String processedRefreshToken) throws IdentityOAuth2Exception {
        return null;
    }

    /**
     * Method to generate hash value
     * @param plainText
     * @return hashed value
     */
    private String hash(String plainText) {

        String hashAlgorithm = OAuthServerConfiguration.getInstance().getHashAlgorithm();
        if (plainText != null) {
            if ("SHA256".equals(hashAlgorithm)) {
                return DigestUtils.sha256Hex(plainText);
            } else if ("SHA512".equals(hashAlgorithm)) {
                return DigestUtils.sha512Hex(plainText);
            } else if ("SHA384".equals(plainText)) {
                return DigestUtils.sha384Hex(plainText);
            } else {
                return DigestUtils.sha256Hex(plainText);
            }
        } else {
            return null;
        }
    }
}
