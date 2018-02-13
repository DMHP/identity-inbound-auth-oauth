/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * JDBC Based data access layer for OAuth Consumer Applications.
 */
public class OAuthAppDAO {

    public static final Log log = LogFactory.getLog(OAuthAppDAO.class);
    private TokenPersistenceProcessor persistenceProcessor;

    public OAuthAppDAO() {

        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextPersistenceProcessor");
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }
    }

    public void addOAuthApplication(OAuthAppDO consumerAppDO) throws IdentityOAuthAdminException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        if (!isDuplicateApplication(consumerAppDO.getUser().getUserName(), IdentityTenantUtil.getTenantId(consumerAppDO
                .getUser().getTenantDomain()), consumerAppDO.getUser().getUserStoreDomain(), consumerAppDO)) {

            try {
                if(OAuth2ServiceComponentHolder.isPkceEnabled()) {
                    prepStmt = getAddAppPreparedStatementWithPKCE(connection, consumerAppDO);
                    prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerAppDO.getOauthConsumerKey()));
                    prepStmt.setString(3, consumerAppDO.getUser().getUserName());
                    prepStmt.setInt(4, IdentityTenantUtil.getTenantId(consumerAppDO.getUser().getTenantDomain()));
                    prepStmt.setString(5, consumerAppDO.getUser().getUserStoreDomain());
                    prepStmt.setString(6, consumerAppDO.getApplicationName());
                    prepStmt.setString(7, consumerAppDO.getOauthVersion());
                    prepStmt.setString(8, consumerAppDO.getCallbackUrl());
                    prepStmt.setString(9, consumerAppDO.getGrantTypes());
                    prepStmt.setString(10, consumerAppDO.isPkceMandatory() ? "1" : "0");
                    prepStmt.setString(11, consumerAppDO.isPkceSupportPlain() ? "1" : "0");
                    prepStmt.execute();
                    connection.commit();
                } else {
                    prepStmt = getAddAppPreparedStatementWithoutPKCE(connection, consumerAppDO);
                    prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerAppDO.getOauthConsumerKey()));
                    prepStmt.setString(3, consumerAppDO.getUser().getUserName());
                    prepStmt.setInt(4, IdentityTenantUtil.getTenantId(consumerAppDO.getUser().getTenantDomain()));
                    prepStmt.setString(5, consumerAppDO.getUser().getUserStoreDomain());
                    prepStmt.setString(6, consumerAppDO.getApplicationName());
                    prepStmt.setString(7, consumerAppDO.getOauthVersion());
                    prepStmt.setString(8, consumerAppDO.getCallbackUrl());
                    prepStmt.setString(9, consumerAppDO.getGrantTypes());
                    prepStmt.execute();
                    connection.commit();
                }

            } catch (SQLException e) {
                throw new IdentityOAuthAdminException("Error when executing the SQL : " +
                        SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP, e);
            } catch (IdentityOAuth2Exception e) {
                throw new IdentityOAuthAdminException("Error occurred while processing the client id and client " +
                        "secret by TokenPersistenceProcessor");
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
            }
        } else {
            throw new IdentityOAuthAdminException("Error when adding the consumer application. " +
                    "An application with the same name already exists.");
        }
    }

    public String[] addOAuthConsumer(String username, int tenantId, String userDomain) throws IdentityOAuthAdminException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String sqlStmt = null;
        String consumerKey;
        String consumerSecret = OAuthUtil.getRandomNumber();

        do {
            consumerKey = OAuthUtil.getRandomNumber();
        }
        while (isDuplicateConsumer(consumerKey));

        try {
            sqlStmt = SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER;
            prepStmt = connection.prepareStatement(sqlStmt);
            prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);
            prepStmt.setString(3, username);
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, userDomain);
            // it is assumed that the OAuth version is 1.0a because this is required with OAuth 1.0a
            prepStmt.setString(6, OAuthConstants.OAuthVersions.VERSION_1A);
            prepStmt.execute();

            connection.commit();

        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when executing the SQL : " + sqlStmt, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return new String[]{consumerKey, consumerSecret};
    }

    public OAuthAppDO[] getOAuthConsumerAppsOfUser(String username, int tenantId) throws IdentityOAuthAdminException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;
        OAuthAppDO[] oauthAppsOfUser;
        List<ConsumerSecret> consumerSecretList = new ArrayList<>();

        try {
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
            String tenantDomain = realmService.getTenantManager().getDomain(tenantId);
            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
            String tenantUnawareUserName = tenantAwareUserName + "@" + tenantDomain;
            boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(tenantUnawareUserName);
            boolean isPKCESupportEnabled = OAuth2ServiceComponentHolder.isPkceEnabled();

            String sql = null;
            if(isPKCESupportEnabled) {
                sql = SQLQueries.OAuthAppDAOSQLQueries.GET_APPS_OF_USER_WITH_TENANTAWARE_OR_TENANTUNAWARE_USERNAME_WITH_PKCE;
            } else {
                sql = SQLQueries.OAuthAppDAOSQLQueries.GET_APPS_OF_USER_WITH_TENANTAWARE_OR_TENANTUNAWARE_USERNAME;
            }

            if (!isUsernameCaseSensitive) {
                sql = sql.replace("USERNAME", "LOWER(USERNAME)");
            }
            prepStmt = connection.prepareStatement(sql);
            if (isUsernameCaseSensitive) {
                prepStmt.setString(1, tenantAwareUserName);
                prepStmt.setString(2, tenantUnawareUserName);
            } else {
                prepStmt.setString(1, tenantAwareUserName.toLowerCase());
                prepStmt.setString(2, tenantUnawareUserName.toLowerCase());
            }

            prepStmt.setInt(3, tenantId);

            rSet = prepStmt.executeQuery();
            List<OAuthAppDO> oauthApps = new ArrayList<OAuthAppDO>();
            while (rSet.next()) {
                if (rSet.getString(3) != null && rSet.getString(3).length() > 0) {
                    OAuthAppDO oauthApp = new OAuthAppDO();
                    oauthApp.setOauthConsumerKey(persistenceProcessor.getPreprocessedClientId(rSet.getString(1)));
                    oauthApp.setOauthConsumerSecret(
                            persistenceProcessor.getPreprocessedClientSecret(rSet.getString(2)));
                    oauthApp.setApplicationName(rSet.getString(3));
                    oauthApp.setOauthVersion(rSet.getString(4));
                    oauthApp.setCallbackUrl(rSet.getString(5));
                    oauthApp.setGrantTypes(rSet.getString(6));
                    oauthApp.setId(rSet.getInt(7));
                    AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                    authenticatedUser.setUserName(rSet.getString(8));
                    authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(rSet.getInt(9)));
                    authenticatedUser.setUserStoreDomain(rSet.getString(10));
                    if(isPKCESupportEnabled) {
                        oauthApp.setPkceMandatory("0".equals(rSet.getString(11)) ? false : true);
                        oauthApp.setPkceSupportPlain("0".equals(rSet.getString(12)) ? false : true);
                    }
                    oauthApp.setUser(authenticatedUser);
                    oauthApps.add(oauthApp);

                    // This method is to gather list of client secrets that need to be migrated if it is encrypted
                    // with plain RSA.This migration need to be done only if new encryption algorithm of OAEP is
                    // enabled via carbon.properties file.
                    addClientSecretToBeMigrated(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(2)),
                            rSet.getString(2), consumerSecretList);
                }
            }
            oauthAppsOfUser = oauthApps.toArray(new OAuthAppDO[oauthApps.size()]);
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error occurred while retrieving OAuth consumer apps of user", e);
        } catch (UserStoreException e) {
            throw new IdentityOAuthAdminException("Error while retrieving Tenant Domain for tenant ID : " + tenantId, e);
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuthAdminException("Error occurred while processing client id and client secret by " +
                    "TokenPersistenceProcessor", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }

        try {
            //migrate the list of client secrets that was encrypted with plain RSA to RSA+OAEP encrypted algorithm.
            //Since this requires an UPDATE operation, call it after the above GET operation is completed.
            migrateListOfClientSecrets(consumerSecretList);
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuthAdminException(e.getMessage(), e);
        }
        return oauthAppsOfUser;
    }

    public OAuthAppDO getAppInformation(String consumerKey) throws InvalidOAuthClientException, IdentityOAuth2Exception {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;
        OAuthAppDO oauthApp = null;
        boolean isPKCESupportEnabled = OAuth2ServiceComponentHolder.isPkceEnabled();
        List<ConsumerSecret> consumerSecretList = new ArrayList<>();
        try {
            if (isPKCESupportEnabled) {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_WITH_PKCE);
            } else {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO);
            }

            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));

            rSet = prepStmt.executeQuery();
            List<OAuthAppDO> oauthApps = new ArrayList<>();
            /**
             * We need to determine whether the result set has more than 1 row. Meaning, we found an application for
             * the given consumer key. There can be situations where a user passed a key which doesn't yet have an
             * associated application. We need to barf with a meaningful error message for this case
             */
            boolean rSetHasRows = false;
            while (rSet.next()) {
                // There is at least one application associated with a given key
                rSetHasRows = true;
                if (rSet.getString(4) != null && rSet.getString(4).length() > 0) {
                    oauthApp = new OAuthAppDO();
                    oauthApp.setOauthConsumerKey(consumerKey);
                    oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(1)));
                    AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                    authenticatedUser.setUserName(rSet.getString(2));
                    oauthApp.setApplicationName(rSet.getString(3));
                    oauthApp.setOauthVersion(rSet.getString(4));
                    oauthApp.setCallbackUrl(rSet.getString(5));
                    authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(rSet.getInt(6)));
                    authenticatedUser.setUserStoreDomain(rSet.getString(7));
                    oauthApp.setUser(authenticatedUser);
                    oauthApp.setGrantTypes(rSet.getString(8));
                    oauthApp.setId(rSet.getInt(9));
                    if (isPKCESupportEnabled) {
                        oauthApp.setPkceMandatory("0".equals(rSet.getString(10)) ? false : true);
                        oauthApp.setPkceSupportPlain("0".equals(rSet.getString(11)) ? false : true);
                    }
                    oauthApps.add(oauthApp);

                    // This method to gather list of client secrets that need to be migrated if it is encrypted
                    // with plain RSA.This migration need to be done only if new encryption algorithm of OAEP is
                    // enabled via carbon.properties file.
                    addClientSecretToBeMigrated(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(1)),
                            rSet.getString(1), consumerSecretList);
                }
            }
            if (!rSetHasRows) {
                /**
                 * We come here because user submitted a key that doesn't have any associated application with it.
                 * We're throwing an error here because we cannot continue without this info. Otherwise it'll throw
                 * a null values not supported error when it tries to cache this info
                 */

                throw new InvalidOAuthClientException("Cannot find an application associated with the given consumer key : " + consumerKey);
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving the app information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }

        //migrate the list of client secrets that was encrypted with plain RSA to RSA+OAEP encrypted algorithm.
        //Since this requires an UPDATE operation, call it after the above GET operation is completed.
        migrateListOfClientSecrets(consumerSecretList);
        return oauthApp;
    }

    public OAuthAppDO getAppInformationByAppName(String appName) throws InvalidOAuthClientException, IdentityOAuth2Exception {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;
        OAuthAppDO oauthApp = null;
        boolean isPKCESupportEnabled = OAuth2ServiceComponentHolder.isPkceEnabled();
        List<ConsumerSecret> consumerSecretList = new ArrayList<>();
        try {
            int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
            if (isPKCESupportEnabled) {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_BY_APP_NAME_WITH_PKCE);
            } else {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_BY_APP_NAME);
            }

            prepStmt.setString(1, appName);
            prepStmt.setInt(2, tenantID);

            rSet = prepStmt.executeQuery();
            List<OAuthAppDO> oauthApps = new ArrayList<>();
            oauthApp = new OAuthAppDO();
            oauthApp.setApplicationName(appName);
            AuthenticatedUser user = new AuthenticatedUser();
            user.setTenantDomain(IdentityTenantUtil.getTenantDomain(tenantID));
            /**
             * We need to determine whether the result set has more than 1 row. Meaning, we found an application for
             * the given consumer key. There can be situations where a user passed a key which doesn't yet have an
             * associated application. We need to barf with a meaningful error message for this case
             */
            boolean rSetHasRows = false;
            while (rSet.next()) {
                // There is at least one application associated with a given key
                rSetHasRows = true;
                if (rSet.getString(4) != null && rSet.getString(4).length() > 0) {
                    oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(1)));
                    user.setUserName(rSet.getString(2));
                    user.setUserStoreDomain(rSet.getString(3));
                    oauthApp.setUser(user);
                    oauthApp.setOauthConsumerKey(persistenceProcessor.getPreprocessedClientId(rSet.getString(4)));
                    oauthApp.setOauthVersion(rSet.getString(5));
                    oauthApp.setCallbackUrl(rSet.getString(6));
                    oauthApp.setGrantTypes(rSet.getString(7));
                    oauthApp.setId(rSet.getInt(8));
                    if(isPKCESupportEnabled) {
                        oauthApp.setPkceMandatory("0".equals(rSet.getString(9)) ? false : true);
                        oauthApp.setPkceSupportPlain("0".equals(rSet.getString(10)) ? false : true);
                    }
                    oauthApps.add(oauthApp);
                    // This method is to gather list of client secrets that need to be migrated if it is encrypted
                    // with plain RSA.This migration need to be done only if new encryption algorithm of OAEP is
                    // enabled via carbon.properties file.
                    addClientSecretToBeMigrated(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(1)),
                            rSet.getString(1),consumerSecretList);
                }
            }
            if (!rSetHasRows) {
                /**
                 * We come here because user submitted a key that doesn't have any associated application with it.
                 * We're throwing an error here because we cannot continue without this info. Otherwise it'll throw
                 * a null values not supported error when it tries to cache this info
                 */
                String message = "Cannot find an application associated with the given consumer key : " + appName;
                if(log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw new InvalidOAuthClientException(message);
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving the app information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        //migrate the list of client secrets that was encrypted with plain RSA to RSA+OAEP encrypted algorithm.
        //Since this requires an UPDATE operation, call it after the above GET operation is completed.
        migrateListOfClientSecrets(consumerSecretList);
        return oauthApp;
    }

    public void updateConsumerApplication(OAuthAppDO oauthAppDO) throws IdentityOAuthAdminException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        List<ConsumerSecret> consumerSecretList = new ArrayList<>();
        try {
            if (OAuth2ServiceComponentHolder.isPkceEnabled()) {
                prepStmt = getUpdateAppPreparedStatementWithPKCE(connection, oauthAppDO);
            } else {
                prepStmt = getUpdateAppPreparedStatementWithoutPKCE(connection, oauthAppDO);
            }

            prepStmt.setString(1, oauthAppDO.getApplicationName());
            prepStmt.setString(2, oauthAppDO.getCallbackUrl());
            prepStmt.setString(3, oauthAppDO.getGrantTypes());
            if(OAuth2ServiceComponentHolder.isPkceEnabled()) {
                prepStmt.setString(4, oauthAppDO.isPkceMandatory() ? "1" : "0");
                prepStmt.setString(5, oauthAppDO.isPkceSupportPlain() ? "1" : "0");

                prepStmt.setString(6, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
            } else {
                prepStmt.setString(4, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
            }

            int count = prepStmt.executeUpdate();
            if (log.isDebugEnabled()) {
                log.debug("No. of records updated for updating consumer application. : " + count);
            }
            if (count == 0) {
                //If update is not successful check if there is consumer secrets encrypted with Plain RSA when using
                // new encryption algorithm enabled via carbon.properties file.If so, execute the update query using
                // plain RSA algorithm.
                updateConsumerApplicationWithOldRSA(connection,oauthAppDO, consumerSecretList);
            }
            connection.commit();

        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when updating OAuth application", e);
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuthAdminException("Error occurred while processing client id and client secret by " +
                    "TokenPersistenceProcessor", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

        try {
            //migrate the list of client secrets that was encrypted with plain RSA to RSA+OAEP encrypted algorithm.
            migrateListOfClientSecrets(consumerSecretList);
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuthAdminException(e.getMessage(), e);
        }
    }

    public void removeConsumerApplication(String consumerKey) throws IdentityOAuthAdminException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.REMOVE_APPLICATION);
            prepStmt.setString(1, consumerKey);

            prepStmt.execute();
            connection.commit();

        } catch (SQLException e) {;
            throw new IdentityOAuthAdminException("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries.REMOVE_APPLICATION, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Update the OAuth service provider name.
     * @param appName Service provider name.
     * @param consumerKey Consumer key.
     * @throws IdentityApplicationManagementException
     */
    public void updateOAuthConsumerApp(String appName, String consumerKey)
            throws IdentityApplicationManagementException {

        PreparedStatement statement = null;
        Connection connection = null;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            statement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_OAUTH_INFO);
            statement.setString(1, appName);
            statement.setString(2, consumerKey);
            statement.execute();
            connection.setAutoCommit(false);
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, statement);
        }
    }

    public String getConsumerAppState(String consumerKey) throws IdentityOAuthAdminException {
        PreparedStatement prepStmt = null;
        Connection connection = null;
        ResultSet rSet = null;
        String consumerAppState = null;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_APPLICATION_STATE);
            prepStmt.setString(1, consumerKey);
            rSet = prepStmt.executeQuery();
            if(rSet != null && rSet.next()) {
                consumerAppState = rSet.getString("APP_STATE");
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error while executing the SQL prepStmt.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return consumerAppState;
    }

    public void updateConsumerAppState(String consumerKey, String state) throws IdentityApplicationManagementException {
        PreparedStatement statement = null;
        Connection connection = null;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            statement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_APPLICATION_STATE);
            statement.setString(1, state);
            statement.setString(2, consumerKey);
            statement.execute();
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, statement);
        }
    }

    private boolean isDuplicateApplication(String username, int tenantId, String userDomain, OAuthAppDO consumerAppDTO)
            throws IdentityOAuthAdminException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;

        boolean isDuplicateApp = false;
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(username, tenantId);

        try {
            String sql = SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_APPLICATION;
            if (!isUsernameCaseSensitive) {
                sql = sql.replace("USERNAME", "LOWER(USERNAME)");
            }
            prepStmt = connection.prepareStatement(sql);
            if (isUsernameCaseSensitive) {
                prepStmt.setString(1, username);
            } else {
                prepStmt.setString(1, username.toLowerCase());
            }
            prepStmt.setInt(2, tenantId);
            prepStmt.setString(3, userDomain);
            prepStmt.setString(4, consumerAppDTO.getApplicationName());

            rSet = prepStmt.executeQuery();
            if (rSet.next()) {
                isDuplicateApp = true;
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_APPLICATION, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        return isDuplicateApp;
    }

    private boolean isDuplicateConsumer(String consumerKey) throws IdentityOAuthAdminException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rSet = null;

        boolean isDuplicateConsumer = false;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_CONSUMER);
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));

            rSet = prepStmt.executeQuery();
            if (rSet.next()) {
                isDuplicateConsumer = true;
            }
            connection.commit();
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuthAdminException("Error occurred while processing the client id by TokenPersistenceProcessor");
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when executing the SQL : " + SQLQueries
                    .OAuthAppDAOSQLQueries.CHECK_EXISTING_CONSUMER, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSet, prepStmt);
        }
        return isDuplicateConsumer;
    }

    /**
     * Method to encrypt the client secret which was encrypted with old RSA algorithm  with new RSA+OAEP algorithm.
     * This will also store a hashed value of the client secret.
     *
     * @param decryptedClientSecret
     * @param oldEncryptedClientSecret
     * @throws SQLException
     * @throws IdentityOAuth2Exception
     */
    private void updateNewEncryptedClientSecret(PreparedStatement prepStmt, String decryptedClientSecret,
            String oldEncryptedClientSecret) throws SQLException, IdentityOAuth2Exception {

        prepStmt.setString(1, persistenceProcessor.getProcessedClientSecret(decryptedClientSecret));
        prepStmt.setString(2, OAuth2Util.hashClientSecret(decryptedClientSecret));
        prepStmt.setString(3, oldEncryptedClientSecret);
        prepStmt.addBatch();
    }

    /**
     * Method to check whether a particular client secret is encrypted using old RSA algorithm.
     * @param connection
     * @param clientSecret
     * @return
     * @throws SQLException
     * @throws IdentityOAuth2Exception
     */
    private boolean isRsaEncryptedClientSecretAvailable(Connection connection, String clientSecret)
            throws SQLException, IdentityOAuth2Exception {
        PreparedStatement prepStmt ;
        prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.CHECK_CONSUMER_SECRET);
        prepStmt.setString(1, OAuth2Util.encryptWithRSA(clientSecret));
        ResultSet resultSet = prepStmt.executeQuery();
        return resultSet.next();
    }

    /**
     * This method is to migrate plain RSA encrypted client secrets to new RSA+OAEP encrypted format.
     * The migration is only done if new encryption algorithm is enabled via carbon.properties file.
     *
     * @param consumerSecretList list of consumer secrets that need to be migrated to new encryption format.
     * @throws IdentityOAuth2Exception
     */
    private void migrateListOfClientSecrets(List<ConsumerSecret> consumerSecretList) throws IdentityOAuth2Exception {

        if (OAuth2Util.isEncryptionWithTransformationEnabled() && consumerSecretList != null) {
            Connection connection = IdentityDatabaseUtil.getDBConnection();
            PreparedStatement preparedStatement = null;
            try {
                preparedStatement = connection
                        .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_SECRET);
                for (ConsumerSecret consumerSecret : consumerSecretList) {
                    updateNewEncryptedClientSecret(preparedStatement, consumerSecret.decryptedClientSecret,
                            consumerSecret.oldEncryptedClientSecret);
                }
                preparedStatement.executeBatch();
                connection.commit();
            } catch (SQLException e) {
                throw new IdentityOAuth2Exception(
                        "Error while migrating old encrypted consumer secrets to custom encrypted consumer secrets. ",
                        e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
            }
        }
    }

    /**
     * This method will create prepared statement to store newly encrypted(using RSA + OAEP algorithm used in carbon
     * .properties) client secret and hashed
     * client
     * secret when PKCE is enabled. If custom encryption is not enabled, it will store the client secret in the
     * normal flow inside the else statement.
     *
     * @param connection    database connection
     * @param consumerAppDO
     * @return PreparedStatement
     * @throws IdentityOAuth2Exception
     */
    private PreparedStatement getAddAppPreparedStatementWithPKCE(Connection connection, OAuthAppDO consumerAppDO)
            throws IdentityOAuth2Exception {

        PreparedStatement prepStmt;
        try {
            if (OAuth2Util.isEncryptionWithTransformationEnabled()) {
                prepStmt = connection
                        .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP_WITH_PKCE_WITH_HASH);
                prepStmt.setString(12, OAuth2Util.
                        hashClientSecret(consumerAppDO.getOauthConsumerSecret()));
            } else {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP_WITH_PKCE);
            }
            prepStmt.setString(2,
                    persistenceProcessor.getProcessedClientSecret(consumerAppDO.getOauthConsumerSecret()));
            return prepStmt;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(
                    "Error while creating prepared statement to add consumer application with PKCE. ", e);
        }
    }

    /**
     * This method will create prepared statement to store newly encrypted (using RSA + OAEP algorithm used in carbon
     * .properties) client secret and hashed client
     * secret when PKCE is not enabled.
     * If custom encryption is not enabled, it will store the client secret in the normal flow inside the else statement.
     *
     * @param connection    database connection
     * @param consumerAppDO
     * @return PreparedStatement
     * @throws IdentityOAuth2Exception
     */
    private PreparedStatement getAddAppPreparedStatementWithoutPKCE(Connection connection, OAuthAppDO consumerAppDO)
            throws IdentityOAuth2Exception {

        PreparedStatement prepStmt;
        try {
            if (OAuth2Util.isEncryptionWithTransformationEnabled()) {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP_WITH_HASH);
                prepStmt.setString(10, OAuth2Util.hashClientSecret(consumerAppDO.getOauthConsumerSecret()));
            } else {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP);
            }
            prepStmt.setString(2,
                    persistenceProcessor.getProcessedClientSecret(consumerAppDO.getOauthConsumerSecret()));
            return prepStmt;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(
                    "Error while creating prepared statement to add consumer application with out PKCE. ", e);
        }
    }

    /**
     * This method will create prepared statement to search from hashed value of the client secret if new encryption
     * (using RSA + OAEP algorithm used in carbon.properties) algorithm is used and PKCE is enabled.
     * If new encryption is not enabled search will go through normal flow in the else block.
     *
     * @param connection database connection
     * @param oauthAppDO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private PreparedStatement getUpdateAppPreparedStatementWithPKCE(Connection connection, OAuthAppDO oauthAppDO)
            throws IdentityOAuth2Exception {

        PreparedStatement prepStmt;
        try {
            if (OAuth2Util.isEncryptionWithTransformationEnabled()) {
                prepStmt = connection
                        .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP_WITH_PKCE_WITH_HASH);
                prepStmt.setString(7, OAuth2Util.hashClientSecret(oauthAppDO.getOauthConsumerSecret()));
            } else {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP_WITH_PKCE);
                prepStmt.setString(7,
                        persistenceProcessor.getProcessedClientSecret(oauthAppDO.getOauthConsumerSecret()));
            }
            return prepStmt;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(
                    "Error while creating prepared statement to update consumer application" + " with PKCE. ", e);
        }
    }

    /**
     * This method will create prepared statement to search from hashed value of the client secret if new encryption
     * (using RSA + OAEP algorithm used in carbon.properties) algorithm is used and PKCE is not enabled.
     * If new encryption is not enabled search will go through normal flow in the else block.
     *
     * @param connection database connection
     * @param oauthAppDO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private PreparedStatement getUpdateAppPreparedStatementWithoutPKCE(Connection connection, OAuthAppDO oauthAppDO)
            throws IdentityOAuth2Exception {

        PreparedStatement prepStmt;
        try {
            if (OAuth2Util.isEncryptionWithTransformationEnabled()) {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP_WITH_HASH);
                prepStmt.setString(5, OAuth2Util.hashClientSecret(oauthAppDO.getOauthConsumerSecret()));
            } else {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP);
                prepStmt.setString(5,
                        persistenceProcessor.getProcessedClientSecret(oauthAppDO.getOauthConsumerSecret()));
            }
            return prepStmt;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(
                    "Error while creating prepared statement to update consumer application" + " without PKCE. ", e);
        }
    }

    /**
     * This method is used when new encryption is enabled and yet there are some consumer secrets encrypted with
     * plain RSA algorithm. In such cases we need to search using the plain RSA encrypted value and execute the
     * update query. This method will not be used if new encryption algorithm is not enabled in carbon.properties file.
     * Other than that, the consumer secrets that need to be migrated will be put into a list as well.
     *
     * @param connection database connection
     * @param oauthAppDO
     * @param consumerSecretList list of consumer secrets that need to be migrated to new encryption format.
     * @throws IdentityOAuth2Exception
     * @throws SQLException
     */
    private void updateConsumerApplicationWithOldRSA(Connection connection, OAuthAppDO oauthAppDO,
            List<ConsumerSecret> consumerSecretList)
            throws IdentityOAuth2Exception, SQLException {
        //This update operation will happen only if new encryption algorithm is enabled via carbon.properties and
        // there is consumer secret already encrypted with Plain RSA algorithm.
        if (OAuth2Util.isEncryptionWithTransformationEnabled() && isRsaEncryptedClientSecretAvailable(connection,
                oauthAppDO.getOauthConsumerSecret())) {
            PreparedStatement preparedStatement ;
            if (OAuth2ServiceComponentHolder.isPkceEnabled()) {
                preparedStatement = connection
                        .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP_WITH_PKCE);
            } else {
                preparedStatement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP);
            }
            preparedStatement.setString(1, oauthAppDO.getApplicationName());
            preparedStatement.setString(2, oauthAppDO.getCallbackUrl());
            preparedStatement.setString(3, oauthAppDO.getGrantTypes());
            if (OAuth2ServiceComponentHolder.isPkceEnabled()) {
                preparedStatement.setString(4, oauthAppDO.isPkceMandatory() ? "1" : "0");
                preparedStatement.setString(5, oauthAppDO.isPkceSupportPlain() ? "1" : "0");

                preparedStatement
                        .setString(6, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
                preparedStatement.setString(7, OAuth2Util.encryptWithRSA(oauthAppDO.getOauthConsumerSecret()));
                addClientSecretToBeMigrated(oauthAppDO.getOauthConsumerSecret(),
                        OAuth2Util.encryptWithRSA(oauthAppDO.getOauthConsumerSecret()), consumerSecretList);
            } else {
                preparedStatement
                        .setString(4, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
                preparedStatement.setString(5, OAuth2Util.encryptWithRSA(oauthAppDO.getOauthConsumerSecret()));
                addClientSecretToBeMigrated(oauthAppDO.getOauthConsumerSecret(),
                        OAuth2Util.encryptWithRSA(oauthAppDO.getOauthConsumerSecret()), consumerSecretList);
            }
            int count = preparedStatement.executeUpdate();
            if (log.isDebugEnabled()) {
                log.debug("No. of records updated for updating consumer application. : " + count);
            }
        }
    }

    /**
     * This method add client secret that is encrypted with plain RSA in to a list.
     * This list will be later used to migrate those client secrets into new RSA+OAEP algorithm.
     *
     * @param decryptedClientSecret
     * @param encryptedClientSecret
     * @param consumerSecretList list of consumer secrets that need to be migrated to new encryption format.
     * @throws IdentityOAuth2Exception
     */
    private void addClientSecretToBeMigrated(String decryptedClientSecret, String encryptedClientSecret,
            List<ConsumerSecret> consumerSecretList) throws IdentityOAuth2Exception {

        if (OAuth2Util.isEncryptionWithTransformationEnabled() && !OAuth2Util
                .isSelfContainedCiphertext(encryptedClientSecret)) {
            consumerSecretList.add(new ConsumerSecret(decryptedClientSecret, encryptedClientSecret));
        }
    }

    /**
     * Inner class to hold client secret and encrypted client secret (using old RSA).
     * This inner class is used for migration purposes of plain RSA encrypted client secrets to new encrypted client
     * secrets. If new encryption of RSA+OAEP is not enabled via carbon.properties and migration is not needed, this
     * inner class will not be used.
     */
    private class ConsumerSecret {

        String decryptedClientSecret;
        String oldEncryptedClientSecret;

        ConsumerSecret(String clientSecret, String encryptedClientSecret) {
            this.decryptedClientSecret = clientSecret;
            this.oldEncryptedClientSecret = encryptedClientSecret;
        }

    }

}
