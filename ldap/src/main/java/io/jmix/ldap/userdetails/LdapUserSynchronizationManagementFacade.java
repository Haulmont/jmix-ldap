package io.jmix.ldap.userdetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jmx.export.annotation.ManagedOperation;
import org.springframework.jmx.export.annotation.ManagedOperationParameter;
import org.springframework.jmx.export.annotation.ManagedOperationParameters;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Component;

@ManagedResource(description = "Synchronized LDAP users from the given LDAP group", objectName = "jmix.ldap:type=LdapUserSynchronization")
@Component("ldap_LdapUserSynchronizationManagementFacade")
public class LdapUserSynchronizationManagementFacade {
    @Autowired(required = false)
    protected LdapUserSynchronizationManager ldapUserSynchronizationManager;

    @ManagedOperation(description = "Synchronized LDAP users from the given LDAP group")
    @ManagedOperationParameters({
            @ManagedOperationParameter(name = "groupCn", description = "LDAP group cn")})
    public String synchronizeUsersFromGroup(String groupCn) {
        if (ldapUserSynchronizationManager != null) {
            ldapUserSynchronizationManager.synchronizeUsersFromGroup(groupCn);
            return "Synchronized successfully";
        } else {
            return "LdapUserSynchronizationManager is not configured";
        }
    }
}
