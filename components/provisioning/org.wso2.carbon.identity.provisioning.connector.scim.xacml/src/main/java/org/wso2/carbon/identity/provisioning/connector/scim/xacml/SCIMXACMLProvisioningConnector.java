package org.wso2.carbon.identity.provisioning.connector.scim.xacml;

import edu.emory.mathcs.backport.java.util.Arrays;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.entitlement.proxy.Attribute;
import org.wso2.carbon.identity.entitlement.proxy.PEPProxy;
import org.wso2.carbon.identity.entitlement.proxy.PEPProxyConfig;
import org.wso2.carbon.identity.entitlement.proxy.ProxyConstants;
import org.wso2.carbon.identity.entitlement.proxy.exception.EntitlementProxyException;
import org.wso2.carbon.identity.provisioning.*;
import org.wso2.carbon.identity.provisioning.connector.scim.SCIMProvisioningConnector;
import org.wso2.carbon.identity.scim.common.impl.ProvisioningClient;
import org.wso2.carbon.identity.scim.common.utils.AttributeMapper;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.charon.core.config.SCIMConfigConstants;
import org.wso2.charon.core.config.SCIMProvider;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.schema.SCIMConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SCIMXACMLProvisioningConnector extends SCIMProvisioningConnector {
    private static final long serialVersionUID = 1602492367923090173L;
    public static final String PROVISIONING_IDP_SELECTOR = "ProvisioningIDPSelector";
    private static Log log = LogFactory.getLog(SCIMXACMLProvisioningConnector.class);
    private String provisioningIDP;
    private String xacmlConnectionUsername;
    private String xacmlConnectionUserPassword;
    private String xacmlServerURL;
    private String xacmlEnvironment;

    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        super.init(provisioningProperties);
        if (provisioningProperties != null && provisioningProperties.length > 0) {

            for (Property property : provisioningProperties) {

                if ("identityProviderName".equals(property.getName())) {
                    provisioningIDP = property.getValue() != null ? property.getValue()
                                                                  : property.getDefaultValue();
                } else if (SCIMXACMLProvisioningConnectorFactory.XACML_SERVER_URL.equals(property.getName())) {
                    xacmlServerURL = property.getValue() != null ? property.getValue()
                                                                 : property.getDefaultValue();
                } else if (SCIMXACMLProvisioningConnectorFactory.XACML_CONNECTION_USERNAME.equals(property.getName())) {
                    xacmlConnectionUsername = property.getValue() != null ? property.getValue()
                                                                          : property.getDefaultValue();
                } else if (SCIMXACMLProvisioningConnectorFactory.XACML_CONNECTION_USER_PASSWORD.equals(
                        property.getName())) {
                    xacmlConnectionUserPassword = property.getValue() != null ? property.getValue()
                                                                              : property.getDefaultValue();
                } else if (SCIMXACMLProvisioningConnectorFactory.XACML_ENVIRONMENT_NAME.equals(
                        property.getName())) {
                    xacmlEnvironment = property.getValue() != null ? property.getValue()
                                                                   : property.getDefaultValue();
                }
            }

        }

    }


    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {

        if (provisioningEntity != null) {

            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for SCIM connector");
                return null;
            }


            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                Map<String, Set<String>> allowedProvisioningUserstores = getAllowedProvisioningUserstores(
                        provisioningEntity);
                if (allowedProvisioningUserstores.size() > 0 &&
                    allowedProvisioningUserstores.containsKey(provisioningIDP)) {
                    if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                        deleteUser(provisioningEntity);
                    } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                        createUser(provisioningEntity);
                        createGroupsWithAllowedGroups(provisioningEntity, allowedProvisioningUserstores);
                        updateGroupsWithAllowedGroups(provisioningEntity, allowedProvisioningUserstores);

                    } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                        updateUser(provisioningEntity);
                    } else {
                        log.warn("Unsupported provisioning operation.");
                    }
                } else {
                    log.info("===============Provisioning is not Done.===================IDP:" + provisioningIDP +
                             " IDP size:" + allowedProvisioningUserstores.size());

                }

            } else if (provisioningEntity.getEntityType() == ProvisioningEntityType.GROUP) {
                if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteGroup(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    createGroup(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                    updateGroup(provisioningEntity);
                } else {
                    log.warn("Unsupported provisioning entity.");
                }
            } else {
                log.warn("Unsupported provisioning operation.");
            }

        }

        return null;

    }

    private void createGroupsWithAllowedGroups(ProvisioningEntity provisioningEntity,
                                               Map<String, Set<String>> allowedProvisioningUserstores) {
        Set<String> allowedRoles = allowedProvisioningUserstores.get(provisioningIDP);
        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri("org:wso2:carbon:identity:provisioning:claim:group");
        claimMapping.setLocalClaim(claim);
        Map<ClaimMapping, List<String>> claimMappingListMap = new HashMap<ClaimMapping, List<String>>();
        claimMappingListMap.put(claimMapping, new ArrayList<String>(allowedRoles));
        ProvisioningEntity provisioningEntity1 = new ProvisioningEntity(ProvisioningEntityType.GROUP,
                                                                        provisioningEntity.getEntityName(),
                                                                        ProvisioningOperation.POST,
                                                                        claimMappingListMap);
        try {
            createGroup(provisioningEntity1);
        } catch (IdentityProvisioningException e) {
            log.debug("Ignoring the exception in case of group is already provisioned.", e);
        }
    }

    private void updateGroupsWithAllowedGroups(ProvisioningEntity provisioningEntity,
                                               Map<String, Set<String>> allowedProvisioningUserstores)
            throws IdentityProvisioningException {
        Set<String> allowedRoles = allowedProvisioningUserstores.get(provisioningIDP);
        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri("org:wso2:carbon:identity:provisioning:claim:group");
        claimMapping.setLocalClaim(claim);
        Map<ClaimMapping, List<String>> claimMappingListMap = new HashMap<ClaimMapping, List<String>>();
        claimMappingListMap.put(claimMapping, new ArrayList<String>(allowedRoles));
        claimMappingListMap.putAll(provisioningEntity.getAttributes());
        ProvisioningEntity provisioningEntity1 = new ProvisioningEntity(ProvisioningEntityType.GROUP,
                                                                        provisioningEntity.getEntityName(),
                                                                        ProvisioningOperation.PUT,
                                                                        claimMappingListMap);
        patchGroup(provisioningEntity1);
    }


    private Map<String, Set<String>> getAllowedProvisioningUserstores(ProvisioningEntity provisioningEntity) {
        Map<String, Map<String, String>> appToPDPClientConfigMap = new HashMap<String, Map<String, String>>();
        Map<String, String> clientConfigMap = new HashMap<String, String>();
        Map<String, Set<String>> idpRoleMap = new HashMap<String, Set<String>>();

        try {
            clientConfigMap.put("client", ProxyConstants.SOAP);
            clientConfigMap.put("serverUrl", xacmlServerURL);
            clientConfigMap.put("userName", xacmlConnectionUsername);
            clientConfigMap.put("password", xacmlConnectionUserPassword);
            clientConfigMap.put("reuseSession", Boolean.toString(true));

            appToPDPClientConfigMap.put(PROVISIONING_IDP_SELECTOR, clientConfigMap);

            List<Attribute> attributeList = new ArrayList<Attribute>();
            Attribute environmentAttribute = new Attribute(
                    "urn:oasis:names:tc:xacml:3.0:attribute-category:environment",
                    "urn:oasis:names:tc:xacml:1.0:environment:environment-id", ProxyConstants.DEFAULT_DATA_TYPE,
                    xacmlEnvironment);
            attributeList.add(environmentAttribute);

            Map<ClaimMapping, List<String>> claimMappingsMap = provisioningEntity.getAttributes();

            for (Map.Entry<ClaimMapping, List<String>> claimMappings : claimMappingsMap.entrySet()) {
                ClaimMapping claimMapping = claimMappings.getKey();

                List<String> claimValues = claimMappings.getValue();
                if (claimValues != null && claimValues.size() > 0 && !StringUtils.isEmpty(claimValues.get(0)) &&
                    !"org:wso2:carbon:identity:provisioning:claim:password".equals(
                            claimMapping.getLocalClaim().getClaimUri()) &&
                    !"org:wso2:carbon:identity:provisioning:claim:group".equals(
                            claimMapping.getLocalClaim().getClaimUri())) {
                    if ("org:wso2:carbon:identity:provisioning:claim:username".equals(
                            claimMapping.getLocalClaim().getClaimUri())) {
                        Attribute subjectAttribute = new Attribute(
                                "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
                                "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
                                ProxyConstants.DEFAULT_DATA_TYPE, claimValues.get(0));
                        attributeList.add(subjectAttribute);
                    } else {
                        attributeList.add(new Attribute("urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
                                                        claimMapping.getLocalClaim().getClaimUri(),
                                                        ProxyConstants.DEFAULT_DATA_TYPE, claimValues.get(0)));
                    }

                }
            }

            PEPProxyConfig config = new PEPProxyConfig(appToPDPClientConfigMap, PROVISIONING_IDP_SELECTOR, "simple", 5,
                                                       1000);
            PEPProxy pepProxy = new PEPProxy(config);
            String result = pepProxy.getDecision(attributeList.toArray(new Attribute[attributeList.size()]),
                                                 PROVISIONING_IDP_SELECTOR);
            if (!StringUtils.isEmpty(result)) {
                OMElement decisionElement = AXIOMUtil.stringToOM(result);
                OMNamespace omNamespace = decisionElement.getDefaultNamespace();
                String nameSpace = null, decisionText = null;
                if (omNamespace != null) {
                    nameSpace = omNamespace.getNamespaceURI();
                }
                if (nameSpace == null) {
                    decisionText = decisionElement.getFirstChildWithName(new QName("Result")).
                            getFirstChildWithName(new QName("Decision")).getText();
                } else {
                    decisionText = decisionElement.getFirstChildWithName(new QName(nameSpace, "Result")).
                            getFirstChildWithName(new QName(nameSpace, "Decision")).getText();
                }

                if (!org.wso2.carbon.utils.xml.StringUtils.isEmpty(decisionText) &&
                    "permit".equalsIgnoreCase(decisionText)) {
                    Iterator obligations = ((OMElement) decisionElement.getFirstElement().getChildrenWithName(
                            new QName("Obligations")).next()).getChildrenWithName(
                            new QName("Obligation"));
                    while (obligations.hasNext()) {
                        OMElement obligation = (OMElement) obligations.next();
                        Iterator attributeAssignments = obligation.getChildrenWithName(
                                new QName("AttributeAssignment"));
                        while (attributeAssignments.hasNext()) {
                            OMElement attributeAssignment = (OMElement) attributeAssignments.next();
                            String idpRoleText = attributeAssignment.getText();
                            if (!StringUtils.isEmpty(idpRoleText)) {
                                idpRoleText = idpRoleText.trim();
                            }
                            if (idpRoleText.contains(":")) {
                                String[] parts = idpRoleText.split(":");
                                Set<String> currentRoleList = idpRoleMap.get(parts[0]);
                                if (currentRoleList == null) {
                                    currentRoleList = new HashSet<String>();
                                    currentRoleList.add(parts[1]);
                                    idpRoleMap.put(parts[0], currentRoleList);
                                } else {
                                    currentRoleList.add(parts[1]);
                                }
                            } else {
                                Set<String> currentRoleList = idpRoleMap.get(idpRoleText);
                                if (currentRoleList == null) {
                                    currentRoleList = new HashSet<String>();
                                    idpRoleMap.put(idpRoleText, currentRoleList);
                                }

                            }
                        }

                    }
                }

            }
        } catch (EntitlementProxyException e) {
            log.error("Failed to initialize XACML request builder.", e);
        } catch (Exception e) {
            log.error("Failed to parse XACML response.", e);
        }

        return idpRoleMap;
    }

    /**
     *
     */
    public boolean isEnabled() throws IdentityProvisioningException {
        return true;
    }

}
