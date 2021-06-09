package io.jmix.ldap;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

@ConfigurationProperties(prefix = "jmix.ldap")
@ConstructorBinding
public class LdapProperties {
    boolean enabled;
    boolean useInternalUserDetailsService;
    List<String> urls;
    String baseDn;
    String managerDn;
    String managerPassword;
    String userSearchBase;
    String userSearchFilter;
    String usernameAttribute;

    String groupRoleAttribute;
    String groupSearchBase;
    boolean groupSearchSubtree;
    String groupSearchFilter;

    //Active Directory
    String activeDirectoryDomain;
    String activeDirectoryRootDn;

    List<String> defaultRoles;
    List<String> standardAuthenticationUsers; //todo: move to security-data?

    public LdapProperties(@DefaultValue("true") boolean enabled,
                          @DefaultValue("false") boolean useInternalUserDetailsService,
                          List<String> urls,
                          String baseDn,
                          String managerDn,
                          String managerPassword,
                          @DefaultValue("") String userSearchBase,
                          String userSearchFilter,
                          @DefaultValue("uid") String usernameAttribute,
                          @DefaultValue("cn") String groupRoleAttribute,
                          @DefaultValue("") String groupSearchBase,
                          @DefaultValue("false") boolean groupSearchSubtree,
                          @DefaultValue("(uniqueMember={0})") String groupSearchFilter,
                          String activeDirectoryDomain,
                          String activeDirectoryRootDn,
                          List<String> defaultRoles,
                          @DefaultValue({"admin"}) List<String> standardAuthenticationUsers) {
        this.enabled = enabled;
        this.useInternalUserDetailsService = useInternalUserDetailsService;
        this.urls = urls;
        this.baseDn = baseDn;
        this.managerDn = managerDn;
        this.managerPassword = managerPassword;
        this.userSearchBase = userSearchBase;
        this.userSearchFilter = userSearchFilter;
        this.usernameAttribute = usernameAttribute;
        this.groupRoleAttribute = groupRoleAttribute;
        this.groupSearchBase = groupSearchBase;
        this.groupSearchSubtree = groupSearchSubtree;
        this.groupSearchFilter = groupSearchFilter;
        this.activeDirectoryDomain = activeDirectoryDomain;
        this.activeDirectoryRootDn = activeDirectoryRootDn;
        this.defaultRoles = defaultRoles;
        this.standardAuthenticationUsers = standardAuthenticationUsers;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isUseInternalUserDetailsService() {
        return useInternalUserDetailsService;
    }

    public List<String> getUrls() {
        return urls;
    }

    public String getBaseDn() {
        return baseDn;
    }

    public String getManagerDn() {
        return managerDn;
    }

    public String getManagerPassword() {
        return managerPassword;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public String getUsernameAttribute() {
        return usernameAttribute;
    }

    public String getGroupRoleAttribute() {
        return groupRoleAttribute;
    }

    public String getGroupSearchBase() {
        return groupSearchBase;
    }

    public boolean isGroupSearchSubtree() {
        return groupSearchSubtree;
    }

    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public String getActiveDirectoryDomain() {
        return activeDirectoryDomain;
    }

    public String getActiveDirectoryRootDn() {
        return activeDirectoryRootDn;
    }

    public List<String> getDefaultRoles() {
        return defaultRoles;
    }

    public List<String> getStandardAuthenticationUsers() {
        return standardAuthenticationUsers;
    }
}

