/*
 * Copyright (c) 2012, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant.saml;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.ClaimsUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.X509CredentialImpl;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * This implements SAML 2.0 Bearer Assertion Profile for OAuth 2.0 -
 * http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-14.
 */
public class SAML2BearerGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final String PROP_IDP_ENTITY_ID = "IdPEntityId";
    private static Log log = LogFactory.getLog(SAML2BearerGrantHandler.class);
    SAMLSignatureProfileValidator profileValidator = null;

    public static final String FEDERATED_USER_DOMAIN_PREFIX = "FEDERATED";
    public static final String LOCAL_USER_TYPE = "LOCAL";
    public static final String LEGACY_USER_TYPE = "LEGACY";

    private final static String INBOUND_AUTH2_TYPE = "oauth2";
    private final static String SP_DIALECT = "http://wso2.org/oidc/claim";

    private static String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

    static {
        UserRealm realm;
        try {
            realm = OAuthComponentServiceHolder.getInstance().getRealmService().getTenantUserRealm
                    (MultitenantConstants.SUPER_TENANT_ID);
            UserStoreManager userStoreManager = realm.getUserStoreManager();
            userAttributeSeparator = ((org.wso2.carbon.user.core.UserStoreManager) userStoreManager)
                    .getRealmConfiguration().getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        } catch (UserStoreException e) {
            log.warn("Error while reading MultiAttributeSeparator value from primary user store ", e);
        }
    }

    @Override
    public void init() throws IdentityOAuth2Exception {

        super.init();

        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(this.getClass().getClassLoader());

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            log.error("Error in bootstrapping the OpenSAML2 library", e);
            throw new IdentityOAuth2Exception("Error in bootstrapping the OpenSAML2 library");
        } finally {
            thread.setContextClassLoader(loader);
        }

        profileValidator = new SAMLSignatureProfileValidator();
    }

    /**
     * We're validating the SAML token that we receive from the request. Through the assertion parameter is the POST
     * request. A request format that we handle here looks like,
     * <p/>
     * POST /token.oauth2 HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * <p/>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer&
     * assertion=PHNhbWxwOl...[omitted for brevity]...ZT4
     *
     * @param tokReqMsgCtx Token message request context
     * @return true if validation is successful, false otherwise
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception
     */
    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if(!super.validateGrant(tokReqMsgCtx)){
            return false;
        }

        Assertion assertion;
        IdentityProvider identityProvider = null;
        String tokenEndpointAlias = null;
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
        if (tenantDomain == null || "".equals(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        // Logging the SAML token
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.SAML_ASSERTION)) {
            log.debug("Received SAML assertion : " +
                            new String(Base64.decodeBase64(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAssertion()))
            );
        }

        try {
            XMLObject samlObject = IdentityUtil.unmarshall(new String(Base64.decodeBase64(
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAssertion())));
            // Validating for multiple assertions
            NodeList assertionList = samlObject.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20_NS, "Assertion");
            if (assertionList.getLength() > 0) {
                log.error("Invalid schema for SAML2 Assertion. Nested assertions detected.");
                return false;
            }

            if (samlObject instanceof Assertion) {
                assertion = (Assertion) samlObject;
            } else {
                log.error("Only Assertion objects are validated in SAML2Bearer Grant Type");
                return false;
            }
        } catch (IdentityException e) {
            // fault in the saml2 assertion
            if(log.isDebugEnabled()){
                log.debug("Error while unmashalling the assertion", e);
            }
            return false;
        }

        /*
          The Assertion MUST contain a <Subject> element.  The subject MAY identify the resource owner for whom
          the access token is being requested.  For client authentication, the Subject MUST be the "client_id"
          of the OAuth client.  When using an Assertion as an authorization grant, the Subject SHOULD identify
          an authorized accessor for whom the access token is being requested (typically the resource owner, or
          an authorized delegate).  Additional information identifying the subject/principal of the transaction
          MAY be included in an <AttributeStatement>.
         */
        if (assertion.getSubject() != null) {
            String subjectIdentifier = assertion.getSubject().getNameID().getValue();
            if (StringUtils.isBlank(subjectIdentifier)) {
                if (log.isDebugEnabled()){
                    log.debug("NameID in Assertion cannot be empty");
                }
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find a Subject in the Assertion");
            }
            return false;
        }

        if (assertion.getIssuer() == null || "".equals(assertion.getIssuer().getValue())) {
            if (log.isDebugEnabled()) {
                log.debug("Issuer is empty in the SAML assertion");
            }
            return false;
        } else {
            try {
                identityProvider = IdentityProviderManager.getInstance().
                        getIdPByAuthenticatorPropertyValue(PROP_IDP_ENTITY_ID,
                                assertion.getIssuer().getValue(), tenantDomain, false);
                // IF Federated IDP not found get the resident IDP and check,
                // resident IDP entityID == issuer
                if (identityProvider != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Found an idp with given information. IDP name : " + identityProvider.getIdentityProviderName());
                    }

                    if (isResidentIdp(identityProvider)) {
                        identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);

                        FederatedAuthenticatorConfig[] fedAuthnConfigs =
                                identityProvider.getFederatedAuthenticatorConfigs();
                        String idpEntityId = null;

                        // Get SAML authenticator
                        FederatedAuthenticatorConfig samlAuthenticatorConfig =
                                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                        IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
                        // Get Entity ID from SAML authenticator
                        Property samlProperty = IdentityApplicationManagementUtil.getProperty(
                                samlAuthenticatorConfig.getProperties(),
                                IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
                        if (samlProperty != null) {
                            idpEntityId = samlProperty.getValue();
                        }

                        if (idpEntityId == null || !assertion.getIssuer().getValue().equals(idpEntityId)) {
                            if(log.isDebugEnabled()) {
                                log.debug("SAML Token Issuer verification failed against resident Identity Provider " +
                                        "in tenant : " + tenantDomain + ". Received : " +
                                        assertion.getIssuer().getValue() + ", Expected : " + idpEntityId);
                            }
                            return false;
                        }

                        // Get OpenIDConnect authenticator == OAuth
                        // authenticator
                        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
                        // Get OAuth token endpoint
                        Property oauthProperty = IdentityApplicationManagementUtil.getProperty(
                                oauthAuthenticatorConfig.getProperties(),
                                IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
                        if (oauthProperty != null) {
                            tokenEndpointAlias = oauthProperty.getValue();
                        }
                    } else {
                        // Get Alias from Federated IDP
                        tokenEndpointAlias = identityProvider.getAlias();
                    }
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug("SAML Token Issuer : " + assertion.getIssuer().getValue() +
                                " not registered as a local Identity Provider in tenant : " + tenantDomain);
                    }
                    return false;
                }
            } catch (IdentityProviderManagementException e) {
                throw new IdentityOAuth2Exception("Error while getting an Identity Provider for issuer value : " +
                        assertion.getIssuer().getValue(), e);
            }
        }

        setUser(tokReqMsgCtx, identityProvider, assertion, tenantDomain);
        /*
          The Assertion MUST contain <Conditions> element with an <AudienceRestriction> element with an <Audience>
          element containing a URI reference that identifies the authorization server, or the service provider
          SAML entity of its controlling domain, as an intended audience.  The token endpoint URL of the
          authorization server MAY be used as an acceptable value for an <Audience> element.  The authorization
          server MUST verify that it is an intended audience for the Assertion.
         */

        if (StringUtils.isBlank(tokenEndpointAlias)) {
            if (log.isDebugEnabled()){
                String errorMsg = "Token Endpoint alias has not been configured in the Identity Provider : "
                        + identityProvider.getIdentityProviderName() + " in tenant : " + tenantDomain;
                log.debug(errorMsg);
            }
            return false;
        }

        Conditions conditions = assertion.getConditions();
        if (conditions != null) {
            if (conditions.getNotOnOrAfter() != null) {
                //Set validity period extracted from SAML Assertion
                long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
                tokReqMsgCtx.setValidityPeriod(conditions.getNotOnOrAfter().getMillis() - curTimeInMillis);
            }

            List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
            if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                boolean audienceFound = false;
                for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                    if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                        for (Audience audience : audienceRestriction.getAudiences()) {
                            if (audience.getAudienceURI().equals(tokenEndpointAlias)) {
                                audienceFound = true;
                                break;
                            }
                        }
                    }
                    if (audienceFound) {
                        break;
                    }
                }
                if (!audienceFound) {
                    if (log.isDebugEnabled()) {
                        log.debug("SAML Assertion Audience Restriction validation failed against the Audience : " +
                                tokenEndpointAlias + " of Identity Provider : " +
                                identityProvider.getIdentityProviderName() + " in tenant : " + tenantDomain);
                    }
                    return false;
                }
            } else {
                if (log.isDebugEnabled()) {
                    String message = "SAML Assertion doesn't contain AudienceRestrictions";
                    log.debug(message);
                }
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                String message = "SAML Assertion doesn't contain Conditions";
                log.debug(message);
            }
            return false;
        }


        /*
          The Assertion MUST have an expiry that limits the time window during which it can be used.  The expiry
          can be expressed either as the NotOnOrAfter attribute of the <Conditions> element or as the NotOnOrAfter
          attribute of a suitable <SubjectConfirmationData> element.
         */

        /*
          The <Subject> element MUST contain at least one <SubjectConfirmation> element that allows the
          authorization server to confirm it as a Bearer Assertion.  Such a <SubjectConfirmation> element MUST
          have a Method attribute with a value of "urn:oasis:names:tc:SAML:2.0:cm:bearer".  The
          <SubjectConfirmation> element MUST contain a <SubjectConfirmationData> element, unless the Assertion
          has a suitable NotOnOrAfter attribute on the <Conditions> element, in which case the
          <SubjectConfirmationData> element MAY be omitted. When present, the <SubjectConfirmationData> element
          MUST have a Recipient attribute with a value indicating the token endpoint URL of the authorization
          server (or an acceptable alias).  The authorization server MUST verify that the value of the Recipient
          attribute matches the token endpoint URL (or an acceptable alias) to which the Assertion was delivered.
          The <SubjectConfirmationData> element MUST have a NotOnOrAfter attribute that limits the window during
          which the Assertion can be confirmed.  The <SubjectConfirmationData> element MAY also contain an Address
          attribute limiting the client address from which the Assertion can be delivered.  Verification of the
          Address is at the discretion of the authorization server.
         */

        DateTime notOnOrAfterFromConditions = null;
        Map<DateTime,DateTime> notOnOrAfterFromAndNotBeforeSubjectConfirmations = new HashMap<>();
        boolean bearerFound = false;
        List<String> recipientURLS = new ArrayList<>();

        if (assertion.getConditions() != null && assertion.getConditions().getNotOnOrAfter() != null) {
            notOnOrAfterFromConditions = assertion.getConditions().getNotOnOrAfter();
        }

        DateTime notBeforeConditions = null;
        if (assertion.getConditions() != null && assertion.getConditions().getNotBefore() != null) {
            notBeforeConditions = assertion.getConditions().getNotBefore();
        }

        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if (subjectConfirmations != null && !subjectConfirmations.isEmpty()) {
            for (SubjectConfirmation s : subjectConfirmations) {
                if (s.getMethod() != null) {
                    if (s.getMethod().equals(OAuthConstants.OAUTH_SAML2_BEARER_METHOD)) {
                        bearerFound = true;
                    }
                } else {
                    if (log.isDebugEnabled()){
                        log.debug("Cannot find Method attribute in SubjectConfirmation " + s.toString());
                    }
                    return false;
                }

                if (s.getSubjectConfirmationData() != null) {
                    if (s.getSubjectConfirmationData().getRecipient() != null) {
                        recipientURLS.add(s.getSubjectConfirmationData().getRecipient());
                    }
                    if (s.getSubjectConfirmationData().getNotOnOrAfter() != null || s.getSubjectConfirmationData()
                            .getNotBefore() != null) {
                        notOnOrAfterFromAndNotBeforeSubjectConfirmations.put(s.getSubjectConfirmationData().getNotOnOrAfter(),
                                s.getSubjectConfirmationData().getNotBefore());
                    } else {
                        if (log.isDebugEnabled()){
                            log.debug("Cannot find NotOnOrAfter and NotBefore attributes in " +
                                    "SubjectConfirmationData " +
                                    s.getSubjectConfirmationData().toString());
                        }
                    }
                } else {
                    if (s.getSubjectConfirmationData() == null && notOnOrAfterFromConditions == null) {
                        if (log.isDebugEnabled()){
                            log.debug("Neither can find NotOnOrAfter attribute in Conditions nor SubjectConfirmationData" +
                                    "in SubjectConfirmation " + s.toString());
                        }
                        return false;
                    }

                    if (s.getSubjectConfirmationData() == null && notBeforeConditions == null) {
                        if (log.isDebugEnabled()){
                            log.debug("Neither can find NotBefore attribute in Conditions nor SubjectConfirmationData" +
                                    "in SubjectConfirmation " + s.toString());
                        }
                        return false;
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()){
                log.debug("No SubjectConfirmation exist in Assertion");
            }
            return false;
        }

        if (!bearerFound) {
            if (log.isDebugEnabled()){
                log.debug("Failed to find a SubjectConfirmation with a Method attribute having : " +
                        OAuthConstants.OAUTH_SAML2_BEARER_METHOD);
            }
            return false;
        }

        if (CollectionUtils.isNotEmpty(recipientURLS) && !recipientURLS.contains(tokenEndpointAlias)) {
            if (log.isDebugEnabled()){
                log.debug("None of the recipient URLs match against the token endpoint alias : " + tokenEndpointAlias +
                        " of Identity Provider " + identityProvider.getIdentityProviderName() + " in tenant : " +
                        tenantDomain);
            }
            return false;
        }

        /*
          The authorization server MUST verify that the NotOnOrAfter instant has not passed, subject to allowable
          clock skew between systems.  An invalid NotOnOrAfter instant on the <Conditions> element invalidates
          the entire Assertion.  An invalid NotOnOrAfter instant on a <SubjectConfirmationData> element only
          invalidates the individual <SubjectConfirmation>.  The authorization server MAY reject Assertions with
          a NotOnOrAfter instant that is unreasonably far in the future.  The authorization server MAY ensure
          that Bearer Assertions are not replayed, by maintaining the set of used ID values for the length of
          time for which the Assertion would be considered valid based on the applicable NotOnOrAfter instant.
         */
        long timestampSkewInMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        if (notOnOrAfterFromConditions != null && notOnOrAfterFromConditions.plus(timestampSkewInMillis).isBeforeNow
                ()) {
            // notOnOrAfter is an expired timestamp
            if (log.isDebugEnabled()){
                log.debug("NotOnOrAfter is having an expired timestamp in Conditions element");
            }
            return false;
        }

        if (notBeforeConditions != null && notBeforeConditions.minus(timestampSkewInMillis).isAfterNow()) {
            // notBefore is an early timestamp
            if (log.isDebugEnabled()){
                log.debug("NotBefore is having an early timestamp in Conditions element");
            }
            return false;
        }

        boolean validSubjectConfirmationDataExists = false;
        DateTime notOnOrAfterFromSubjectConfirmations = null;
        if (!notOnOrAfterFromAndNotBeforeSubjectConfirmations.isEmpty()) {
            for (Map.Entry<DateTime, DateTime> entry : notOnOrAfterFromAndNotBeforeSubjectConfirmations.entrySet()) {
                if (entry.getKey() != null) {
                    notOnOrAfterFromSubjectConfirmations = entry.getKey();
                    if (entry.getKey().plus(timestampSkewInMillis).isAfterNow()) {
                        validSubjectConfirmationDataExists = true;
                    }
                }
                if (entry.getValue() != null) {
                    if (entry.getValue().minus(timestampSkewInMillis).isBeforeNow()) {
                        validSubjectConfirmationDataExists = true;
                    }
                }
            }
        }

        if (notOnOrAfterFromConditions == null && notOnOrAfterFromSubjectConfirmations != null) {
            //Set validity period extracted from SAML subject confirmation
            long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
            tokReqMsgCtx.setValidityPeriod(notOnOrAfterFromSubjectConfirmations.getMillis() - curTimeInMillis);
        }

        if (notOnOrAfterFromConditions == null && notOnOrAfterFromAndNotBeforeSubjectConfirmations == null) {
            if (log.isDebugEnabled()) {
                log.debug("No valid NotOnOrAfter element found in either Conditions or SubjectConfirmationData " +
                        "element");
            }
            return false;
        }

        if (notOnOrAfterFromConditions == null && !validSubjectConfirmationDataExists) {
            if (log.isDebugEnabled()){
                log.debug("No valid NotOnOrAfter element found in SubjectConfirmations");
            }
            return false;
        }

        if (notBeforeConditions == null && !validSubjectConfirmationDataExists) {
            if (log.isDebugEnabled()){
                log.debug("No valid NotBefore element found in SubjectConfirmations");
            }
            return false;
        }

        /*
          The Assertion MUST be digitally signed by the issuer and the authorization server MUST verify the
          signature.
         */

        try {
            profileValidator.validate(assertion.getSignature());
        } catch (ValidationException e) {
            // Indicates signature did not conform to SAML Signature profile
            log.error("Signature do not confirm to SAML signature profile.", e);

            return false;
        }

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(identityProvider.getCertificate());
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Error occurred while decoding public certificate of Identity Provider "
                    + identityProvider.getIdentityProviderName() + " for tenant domain " + tenantDomain, e);
        }

        try {
            X509Credential x509Credential = new X509CredentialImpl(x509Certificate);
            SignatureValidator signatureValidator = new SignatureValidator(x509Credential);
            signatureValidator.validate(assertion.getSignature());
            if (log.isDebugEnabled()){
                log.debug("Signature validation successful");
            }
        } catch (ValidationException e) {
            log.error("Error while validating the signature.", e);
            return false;
        }


        /*
          The authorization server MUST verify that the Assertion is valid in all other respects per
          [OASIS.saml-core-2.0-os], such as (but not limited to) evaluating all content within the Conditions
          element including the NotOnOrAfter and NotBefore attributes, rejecting unknown condition types, etc.

          [OASIS.saml-core-2.0-os] - http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
         */


        // TODO: Throw the SAML request through the general SAML2 validation routines

        tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());

        // Storing the Assertion. This will be used in OpenID Connect for example
        tokReqMsgCtx.addProperty(OAuthConstants.OAUTH_SAML2_ASSERTION, assertion);

        // Invoking extension
        SAML2TokenCallbackHandler callback =
                OAuthServerConfiguration.getInstance()
                        .getSAML2TokenCallbackHandler();
        if (callback != null) {
            if (log.isDebugEnabled()){
                log.debug("Invoking the SAML2 Token callback handler ");
            }
            callback.handleSAML2Token(tokReqMsgCtx);
        }

        return true;
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokenReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO responseDTO = super.issue(tokenReqMsgCtx);

        String[] scope = tokenReqMsgCtx.getScope();
        if (OAuth2Util.isOIDCAuthzRequest(scope)) {
            Assertion assertion = (Assertion) tokenReqMsgCtx.getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION);

            if (assertion != null) {
                Map<String, String> attributes = ClaimsUtil.extractClaimsFromAssertion(tokenReqMsgCtx, responseDTO,
                        assertion, userAttributeSeparator);

                String tenantDomain = tokenReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
                if (StringUtils.isBlank(tenantDomain)) {
                    tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                }

                if (attributes != null && attributes.size() > 0) {
                    if (OAuthServerConfiguration.getInstance().isConvertOriginalClaimsFromAssertionsToOIDCDialect()) {

                        IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);

                        boolean localClaimDialect = identityProvider.getClaimConfig().isLocalClaimDialect();
                        ClaimMapping[] idPClaimMappings = identityProvider.getClaimConfig().getClaimMappings();
                        Map<String, String> localClaims;

                        if (isResidentIdp(identityProvider)) {
                            localClaims = handleClaimsForResidentIDP(attributes, identityProvider);
                        } else {
                            localClaims = handleClaimsForIDP(attributes, tenantDomain, identityProvider,
                                    localClaimDialect, idPClaimMappings);
                        }

                        // Handle IdP Role Mappings
                        if (localClaims != null && StringUtils
                                .isNotBlank(localClaims.get(FrameworkConstants.LOCAL_ROLE_CLAIM_URI))) {

                            String updatedRoleClaimValue = getUpdatedRoleClaimValue(identityProvider,
                                    localClaims.get(FrameworkConstants.LOCAL_ROLE_CLAIM_URI));
                            if (updatedRoleClaimValue != null) {
                                localClaims.put(FrameworkConstants.LOCAL_ROLE_CLAIM_URI, updatedRoleClaimValue);
                            } else {
                                localClaims.remove(FrameworkConstants.LOCAL_ROLE_CLAIM_URI);
                                if (localClaims.isEmpty()) {
                                    // This added to handle situation where removing all role mappings and requesting
                                    // the id token using same SAML assertion.
                                    addUserAttributesToCache(responseDTO, tokenReqMsgCtx,
                                            new HashMap<ClaimMapping, String>());
                                }
                            }
                        }

                        // ########################### all claims are in local dialect ############################

                        if (localClaims != null && localClaims.size() > 0) {
                            Map<String, String> oidcClaims;
                            try {
                                oidcClaims = ClaimsUtil.convertClaimsToOIDCDialect(tokenReqMsgCtx,
                                        localClaims);
                            } catch (IdentityApplicationManagementException | IdentityException e) {
                                throw new IdentityOAuth2Exception("Error while converting user claims to OIDC dialect" +
                                        ".");
                            }
                            Map<ClaimMapping, String> claimMappings = FrameworkUtils.buildClaimMappings(oidcClaims);
                            addUserAttributesToCache(responseDTO, tokenReqMsgCtx, claimMappings);
                        }

                    } else {
                        // Not converting claims. Sending the claim uris in original format.
                        Map<ClaimMapping, String> claimMappings = FrameworkUtils.buildClaimMappings(attributes);
                        // Handle IdP Role Mappings
                        for (Iterator<Map.Entry<ClaimMapping, String>> iterator = claimMappings.entrySet()
                                .iterator(); iterator.hasNext(); ) {

                            Map.Entry<ClaimMapping, String> entry = iterator.next();
                            if (FrameworkConstants.LOCAL_ROLE_CLAIM_URI
                                    .equals(entry.getKey().getLocalClaim().getClaimUri()) && StringUtils
                                    .isNotBlank(entry.getValue())) {

                                IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);
                                String updatedRoleClaimValue = getUpdatedRoleClaimValue(identityProvider,
                                        entry.getValue());
                                if (updatedRoleClaimValue != null) {
                                    entry.setValue(updatedRoleClaimValue);
                                } else {
                                    iterator.remove();
                                }
                                break;
                            }
                        }
                        addUserAttributesToCache(responseDTO, tokenReqMsgCtx, claimMappings);
                    }
                }
            }
        }

        return responseDTO;
    }

    /**
     * This method will update the role claim value received from the IdP using the defined role claim configuration
     * for the IdP.
     * Also, if "ReturnOnlyMappedLocalRoles" configuration is enabled, then server will only return the mapped role
     * values.
     *
     * @param identityProvider      identity provide
     * @param currentRoleClaimValue current role claim value.
     * @return updated role claim string
     */
    private String getUpdatedRoleClaimValue(IdentityProvider identityProvider, String currentRoleClaimValue) {

        PermissionsAndRoleConfig permissionAndRoleConfig = identityProvider.getPermissionAndRoleConfig();
        if (permissionAndRoleConfig != null && ArrayUtils.isNotEmpty(permissionAndRoleConfig.getRoleMappings())) {

            String[] receivedRoles = currentRoleClaimValue.split(userAttributeSeparator);
            List<String> updatedRoleClaimValues = new ArrayList<>();
            loop:
            for (String receivedRole : receivedRoles) {
                for (RoleMapping roleMapping : permissionAndRoleConfig.getRoleMappings()) {
                    if (roleMapping.getRemoteRole().equals(receivedRole)) {
                        updatedRoleClaimValues.add(roleMapping.getLocalRole().getLocalRoleName());
                        continue loop;
                    }
                }
                if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
                    updatedRoleClaimValues.add(receivedRole);
                }
            }
            if (!updatedRoleClaimValues.isEmpty()) {
                return StringUtils.join(updatedRoleClaimValues, userAttributeSeparator);
            }
            return null;
        }
        if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
            return currentRoleClaimValue;
        }
        return null;
    }

    protected IdentityProvider getIdentityProvider(Assertion assertion, String tenantDomain) throws IdentityOAuth2Exception {
        IdentityProvider identityProvider;
        try {
            identityProvider = IdentityProviderManager.getInstance().
                    getIdPByAuthenticatorPropertyValue(PROP_IDP_ENTITY_ID,
                            assertion.getIssuer().getValue(), tenantDomain, false);
        } catch (IdentityProviderManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving Identity provider.", e);
        }

        if (isResidentIdp(identityProvider)) {
            try {
                identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
            } catch (IdentityProviderManagementException e) {
                throw new IdentityOAuth2Exception("Error while retrieving resident Identity provider.", e);
            }
        }

        return identityProvider;
    }

    protected boolean isResidentIdp(IdentityProvider identityProvider) {
        return IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME.equals(
                identityProvider.getIdentityProviderName());
    }

    protected Map<String, String> handleClaimsForIDP(Map<String, String> attributes, String tenantDomain,
                                                     IdentityProvider identityProvider, boolean localClaimDialect,
                                                     ClaimMapping[] idPClaimMappings) {
        Map<String, String> localClaims;
        if (localClaimDialect) {
            localClaims = handleLocalClaims(attributes, identityProvider);
        } else {
            if (idPClaimMappings.length > 0) {
                localClaims = ClaimsUtil.convertFederatedClaimsToLocalDialect(attributes, idPClaimMappings,
                        tenantDomain);
                if (log.isDebugEnabled()) {
                    log.debug("IDP claims dialect is not local. Converted claims for " +
                            "identity provider: " + identityProvider.getIdentityProviderName());
                }
            } else {
                localClaims = handleLocalClaims(attributes, identityProvider);
            }
        }
        return localClaims;
    }

    protected Map<String, String> handleClaimsForResidentIDP(Map<String, String> attributes, IdentityProvider
            identityProvider) {
        boolean localClaimDialect;
        Map<String, String> localClaims = new HashMap<>();
        localClaimDialect = identityProvider.getClaimConfig().isLocalClaimDialect();
        if (localClaimDialect) {
            localClaims = handleLocalClaims(attributes, identityProvider);
        } else {
            if (ClaimsUtil.isInLocalDialect(attributes)) {
                localClaims = attributes;
                if (log.isDebugEnabled()) {
                    log.debug("IDP claims dialect is not local. But claims are in local dialect " +
                            "for identity provider: " + identityProvider.getIdentityProviderName() +
                            ". Using attributes in assertion as the IDP claims.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("IDP claims dialect is not local. These claims are not handled for " +
                            "identity provider: " +identityProvider.getIdentityProviderName());
                }
            }

        }
        return localClaims;
    }

    private Map<String, String> handleLocalClaims(Map<String, String> attributes, IdentityProvider identityProvider) {
        Map<String, String> localClaims = new HashMap<>();
        if (ClaimsUtil.isInLocalDialect(attributes)) {
            localClaims = attributes;
            if (log.isDebugEnabled()) {
                log.debug("Claims are in local dialect for " +
                        "identity provider: " + identityProvider.getIdentityProviderName() +
                        ". Using attributes in assertion as the IDP claims.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Claims are not in local dialect " +
                        "for identity provider: " + identityProvider.getIdentityProviderName() +
                        ". Not considering attributes in assertion.");
            }
        }
        return localClaims;
    }

    protected static void addUserAttributesToCache(OAuth2AccessTokenRespDTO tokenRespDTO, OAuthTokenReqMessageContext
            msgCtx, Map<ClaimMapping, String> userAttributes) {

        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(tokenRespDTO
                .getAccessToken());
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);

        if (StringUtils.isNotBlank(tokenRespDTO.getTokenId())) {
            authorizationGrantCacheEntry.setTokenId(tokenRespDTO.getTokenId());
        }

        AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey,
                authorizationGrantCacheEntry);
    }

    /**
     * Set the user identified from subject identifier from assertion
     *
     * @param tokReqMsgCtx     Token Request Message Context
     * @param identityProvider Identity Provider
     * @param assertion        Assertion
     * @param spTenantDomain   Service Provider Tenant Domain.
     * @throws IdentityOAuth2Exception
     */
    protected void setUser(OAuthTokenReqMessageContext tokReqMsgCtx, IdentityProvider identityProvider,
            Assertion assertion, String spTenantDomain) throws IdentityOAuth2Exception {
        if (FEDERATED_USER_DOMAIN_PREFIX
                .equalsIgnoreCase(OAuthServerConfiguration.getInstance().getSaml2BearerTokenUserType())) {
            setFederatedUser(tokReqMsgCtx, assertion, spTenantDomain);
        } else if (LOCAL_USER_TYPE
                .equalsIgnoreCase(OAuthServerConfiguration.getInstance().getSaml2BearerTokenUserType())) {
            try {
                setLocalUser(tokReqMsgCtx, assertion, spTenantDomain);
            } catch (UserStoreException e) {
                throw new IdentityOAuth2Exception("Error while building local user from given assertion", e);
            }
        } else if (
                LEGACY_USER_TYPE.equalsIgnoreCase(OAuthServerConfiguration.getInstance().getSaml2BearerTokenUserType())
                        && assertion.getSubject() != null) {
            createLegacyUser(tokReqMsgCtx, assertion);
        } else {
            if (isResidentIdp(identityProvider)) {
                try {
                    setLocalUser(tokReqMsgCtx, assertion, spTenantDomain);
                } catch (UserStoreException e) {
                    throw new IdentityOAuth2Exception("Error while building local user from given assertion", e);
                }
            } else {
                setFederatedUser(tokReqMsgCtx, assertion, spTenantDomain);
            }
        }
    }

    /**
     * This method is setting the username removing the domain name without checking whether the user is federated
     * or not. This fix has done for support backward capability.
     *
     * @param tokReqMsgCtx Token request message context.
     * @param assertion    SAML2 Assertion.
     */
    protected void createLegacyUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion) {
        //Check whether NameID value is null before call this method.
        String resourceOwnerUserName = assertion.getSubject().getNameID().getValue();
        AuthenticatedUser user = OAuth2Util.getUserFromUserName(resourceOwnerUserName);

        user.setAuthenticatedSubjectIdentifier(resourceOwnerUserName);
        user.setFederatedUser(true);
        tokReqMsgCtx.setAuthorizedUser(user);
    }

    /**
     * Build and set Federated User Object.
     *
     * @param tokReqMsgCtx Token request message context.
     * @param assertion    SAML2 Assertion.
     * @param tenantDomain Tenant Domain.
     */
    protected void setFederatedUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion,
            String tenantDomain) {

        String subjectIdentifier = assertion.getSubject().getNameID().getValue();
        if (log.isDebugEnabled()) {
            log.debug("Setting federated user : " + subjectIdentifier + ". with SP tenant domain : " + tenantDomain);
        }
        AuthenticatedUser user = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(subjectIdentifier);
        user.setUserName(subjectIdentifier);
        user.setTenantDomain(tenantDomain);
        tokReqMsgCtx.setAuthorizedUser(user);
    }

    /**
     * Set the local user to the token req message context after validating the user.
     *
     * @param tokReqMsgCtx   Token Request Message Context
     * @param assertion      SAML2 Assertion
     * @param spTenantDomain Service Provider tenant domain
     * @throws UserStoreException
     * @throws IdentityOAuth2Exception
     */
    protected void setLocalUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion, String spTenantDomain)
            throws UserStoreException, IdentityOAuth2Exception {

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        UserStoreManager userStoreManager = null;
        ServiceProvider serviceProvider = null;

        try {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving service provider for client id : " + tokReqMsgCtx.getOauth2AccessTokenReqDTO()
                        .getClientId() + ". Tenant domain : " + spTenantDomain);
            }
            serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService()
                    .getServiceProviderByClientId(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
                            OAuthConstants.Scope.OAUTH2, spTenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving service provider for client id : " + tokReqMsgCtx
                    .getOauth2AccessTokenReqDTO().getClientId() + " in tenant domain " + spTenantDomain);
        }

        AuthenticatedUser authenticatedUser = buildLocalUser(tokReqMsgCtx, assertion, serviceProvider, spTenantDomain);
        if (log.isDebugEnabled()) {
            log.debug("Setting local user with username :" + authenticatedUser.getUserName() + ". User store domain :"
                    + authenticatedUser.getUserStoreDomain() + ". Tenant domain : " + authenticatedUser
                    .getTenantDomain() + " . Authenticated subjectIdentifier : " + authenticatedUser
                    .getAuthenticatedSubjectIdentifier());
        }

        if (!spTenantDomain.equalsIgnoreCase(authenticatedUser.getTenantDomain()) && !serviceProvider.isSaasApp()) {
            throw new IdentityOAuth2Exception(
                    "Non SaaS app tries to issue token for a different tenant domain. User " + "tenant domain : "
                            + authenticatedUser.getTenantDomain() + ". SP tenant domain : " + spTenantDomain);
        }

        userStoreManager = realmService
                .getTenantUserRealm(IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain()))
                .getUserStoreManager();

        if (log.isDebugEnabled()) {
            log.debug("Checking whether the user exists in local user store");
        }
        boolean isExistingUser = userStoreManager
                .isExistingUser(authenticatedUser.getUsernameAsSubjectIdentifier(true, false));
        if (!isExistingUser) {
            throw new IdentityOAuth2Exception("User " + authenticatedUser.getUsernameAsSubjectIdentifier(true, false)
                    + " doesn't exist in local user store.");
        }
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
    }

    /**
     * Build the local user using subject information in the assertion.
     *
     * @param tokReqMsgCtx   Token message context.
     * @param assertion      SAML2 Assertion
     * @param spTenantDomain Service provider tenant domain
     * @return Authenticated User
     */
    protected AuthenticatedUser buildLocalUser(OAuthTokenReqMessageContext tokReqMsgCtx, Assertion assertion,
            ServiceProvider serviceProvider, String spTenantDomain) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        String subjectIdentifier = assertion.getSubject().getNameID().getValue();
        String userTenantDomain = null;
        if (log.isDebugEnabled()) {
            log.debug("Building local user with assertion subject : " + subjectIdentifier);
        }
        authenticatedUser.setUserStoreDomain(UserCoreUtil.extractDomainFromName(subjectIdentifier));
        authenticatedUser.setUserName(
                MultitenantUtils.getTenantAwareUsername(UserCoreUtil.removeDomainFromName(subjectIdentifier)));

        userTenantDomain = MultitenantUtils.getTenantDomain(subjectIdentifier);
        if (StringUtils.isEmpty(userTenantDomain)) {
            userTenantDomain = spTenantDomain;
        }

        authenticatedUser.setTenantDomain(userTenantDomain);

        setAuthenticatedSubjectIdentifier(serviceProvider, authenticatedUser);

        return authenticatedUser;
    }

    private void setAuthenticatedSubjectIdentifier(ServiceProvider serviceProvider,
            AuthenticatedUser authenticatedUser) {
        String authenticatedSubjectIdentifier = authenticatedUser.getUserName();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        String tenantDomain = authenticatedUser.getTenantDomain();

        if (!authenticatedUser.isFederatedUser() && serviceProvider != null) {
            boolean useUserstoreDomainInLocalSubjectIdentifier = serviceProvider
                    .getLocalAndOutBoundAuthenticationConfig().isUseUserstoreDomainInLocalSubjectIdentifier();
            boolean useTenantDomainInLocalSubjectIdentifier = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                    .isUseTenantDomainInLocalSubjectIdentifier();
            if (useUserstoreDomainInLocalSubjectIdentifier && StringUtils.isNotEmpty(userStoreDomain)) {
                authenticatedSubjectIdentifier = IdentityUtil
                        .addDomainToName(authenticatedUser.getUserName(), userStoreDomain);
            }
            if (useTenantDomainInLocalSubjectIdentifier && StringUtils.isNotEmpty(tenantDomain)) {
                authenticatedSubjectIdentifier = UserCoreUtil
                        .addTenantDomainToEntry(authenticatedSubjectIdentifier, tenantDomain);
            }
        }
        authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);
    }

}
