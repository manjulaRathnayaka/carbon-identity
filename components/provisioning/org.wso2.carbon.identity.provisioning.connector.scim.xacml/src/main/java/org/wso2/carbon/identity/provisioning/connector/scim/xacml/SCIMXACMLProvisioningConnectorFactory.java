/*
 *  Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.provisioning.connector.scim.xacml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.identity.provisioning.connector.scim.SCIMProvisioningConnector;

import java.util.ArrayList;
import java.util.List;

/**
 * @author
 */
public class SCIMXACMLProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    public static final String SCIM = "scim-xacml";
    private static final Log log = LogFactory.getLog(SCIMXACMLProvisioningConnectorFactory.class);
    public static final String XACML_CONNECTION_USERNAME = "xacml-connection-username";
    public static final String XACML_CONNECTION_USER_PASSWORD = "xacml-connection-user-password";
    public static final String XACML_SERVER_URL = "xacml-server-url";
    public static final String XACML_ENVIRONMENT_NAME = "xacml-environment-name";

    /**
     * @throws IdentityProvisioningException
     */
    protected SCIMXACMLProvisioningConnector buildConnector(Property[] provisioningProperties)
            throws IdentityProvisioningException {
        SCIMXACMLProvisioningConnector SCIMXACMLProvisioningConnector = new SCIMXACMLProvisioningConnector();
        SCIMXACMLProvisioningConnector.init(provisioningProperties);

        if (log.isDebugEnabled()) {
            log.debug("Created new connector of type : " + SCIM);
        }
        return SCIMXACMLProvisioningConnector;
    }

    /**
     *
     */
    public String getConnectorType() {
        return SCIM;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property username = new Property();
        username.setName(SCIMProvisioningConnector.SCIM_USERNAME);
        username.setDisplayName("Username");
        username.setDefaultValue("admin");
        username.setRequired(true);
        configProperties.add(username);

        Property password = new Property();
        password.setName(SCIMProvisioningConnector.SCIM_PASSWORD);
        password.setDisplayName("Password");
        password.setConfidential(true);
        password.setRequired(true);
        configProperties.add(password);

        Property userEndpoint = new Property();
        userEndpoint.setName(SCIMProvisioningConnector.SCIM_USER_EP);
        userEndpoint.setDisplayName("User Endpoint");
        userEndpoint.setRequired(true);
        configProperties.add(userEndpoint);

        Property groupEndpoint = new Property();
        groupEndpoint.setName(SCIMProvisioningConnector.SCIM_GROUP_EP);
        groupEndpoint.setDisplayName("Group Endpoint");
        groupEndpoint.setRequired(true);
        configProperties.add(groupEndpoint);

        Property userstoreDomain = new Property();
        userstoreDomain.setName(SCIMProvisioningConnector.SCIM_USERSTORE_DOMAIN);
        userstoreDomain.setDisplayName("User Store Domain");
        configProperties.add(userstoreDomain);


        Property xacmlUsername = new Property();
        xacmlUsername.setName(XACML_CONNECTION_USERNAME);
        xacmlUsername.setDisplayName("XACML Username");
        xacmlUsername.setDescription("XACML Connection user who communicate from PEP.");
        xacmlUsername.setRequired(true);
        configProperties.add(xacmlUsername);

        Property xacmlUserPassword = new Property();
        xacmlUserPassword.setName(XACML_CONNECTION_USER_PASSWORD);
        xacmlUserPassword.setDisplayName("XACML User Password");
        xacmlUserPassword.setDescription("XACML Connection user password.");
        xacmlUserPassword.setConfidential(true);
        xacmlUserPassword.setRequired(true);
        configProperties.add(xacmlUserPassword);

        Property xacmlServiceURL = new Property();
        xacmlServiceURL.setName(XACML_SERVER_URL);
        xacmlServiceURL.setDisplayName("XACML Server URL");
        xacmlServiceURL.setDescription("This URL is for identifying the XACML PDP.");
        xacmlServiceURL.setDefaultValue("https://localhost:9443/services/");
        xacmlServiceURL.setRequired(true);
        configProperties.add(xacmlServiceURL);

        Property xacmlEnvironment = new Property();
        xacmlEnvironment.setName(XACML_ENVIRONMENT_NAME);
        xacmlEnvironment.setDisplayName("XACML Policy Environment Value");
        xacmlEnvironment.setDescription("This value is used to build the XACML request.");
        xacmlEnvironment.setRequired(true);
        configProperties.add(xacmlEnvironment);


        return configProperties;

    }
}
