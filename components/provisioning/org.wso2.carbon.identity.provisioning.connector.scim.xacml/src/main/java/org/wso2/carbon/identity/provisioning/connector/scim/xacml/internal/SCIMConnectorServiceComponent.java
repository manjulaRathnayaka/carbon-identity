package org.wso2.carbon.identity.provisioning.connector.scim.xacml.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.connector.scim.xacml.SCIMXACMLProvisioningConnectorFactory;

/**
 * @scr.component name=
 * "org.wso2.carbon.identity.provisioning.connector.scim.xacml.internal.SCIMConnectorServiceComponent"
 * immediate="true"
 */
public class SCIMConnectorServiceComponent {
    private static Log log = LogFactory.getLog(SCIMConnectorServiceComponent.class);

    protected void activate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Activating SCIMConnectorServiceComponent");
        }

        try {
            SCIMXACMLProvisioningConnectorFactory SCIMXACMLProvisioningConnectorFactory = new SCIMXACMLProvisioningConnectorFactory();
            context.getBundleContext().registerService(AbstractProvisioningConnectorFactory.class.getName(),
                                                       SCIMXACMLProvisioningConnectorFactory, null);
            if (log.isDebugEnabled()) {
                log.debug("SCIM-XACML Provisioning Connector bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating SCIM-XACML Provisioning Connector ", e);
        }
    }
}
