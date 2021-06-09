package io.jmix.ldap.userdetails;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.LdapUtils;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

public class LdapUserSynchronizationManager {

    private static final Logger log = LoggerFactory.getLogger(LdapUserSynchronizationManager.class);

    protected LdapTemplate ldapTemplate;

    protected LdapUserSearch ldapUserSearch;

    protected LdapUserDetailsSynchronizationStrategy synchronizationStrategy;

    protected String groupObjectClass = "groupOfUniqueNames";

    protected String memberAttribute = "uniqueMember";

    protected String usernameAttribute = "uid";

    protected LdapAuthoritiesPopulator authoritiesPopulator;

    /**
     * Obtains LDAP users from the given group and synchronize them using the {@link #synchronizationStrategy}.
     */
    public void synchronizeUsersFromGroup(String groupCn) {
        LdapQuery query = query().attributes(memberAttribute)
                .where("objectclass").is(groupObjectClass)
                .and("cn").is(groupCn);

        List<List<String>> searchResults = ldapTemplate.search(query, (AttributesMapper<List<String>>) attributes -> {
            NamingEnumeration<?> resultEnum = attributes.get(memberAttribute).getAll();
            List<String> result = new ArrayList<>();
            try {
                while (resultEnum.hasMore()) {
                    Object searchResult = resultEnum.next();
                    result.add(String.valueOf(searchResult));
                }
            } catch (NamingException e) {
                throw org.springframework.ldap.support.LdapUtils.convertLdapException(e);
            } finally {
                closeNamingEnumeration(resultEnum);
            }
            return result;
        });

        if (searchResults.isEmpty()) {
            throw new IllegalArgumentException("No users found in the group: " + groupCn);
        } else {
            List<String> userDns = searchResults.iterator().next();

            for (String userDn : userDns) {
                try {
                    String relativeName = LdapUtils.getRelativeName(
                            userDn, ldapTemplate.getContextSource().getReadOnlyContext());
                    DirContextOperations dirContextOperations = ldapTemplate.lookupContext(relativeName);
                    String username = dirContextOperations.getStringAttribute(usernameAttribute);
                    Collection<? extends GrantedAuthority> authorities = Collections.emptyList();
                    if (authoritiesPopulator != null) {
                        authorities = authoritiesPopulator.getGrantedAuthorities(dirContextOperations, username);
                    }
                    if (synchronizationStrategy != null) {
                        synchronizationStrategy.synchronizeUserDetails(dirContextOperations, username, authorities);
                    }
                } catch (NamingException e) {
                    throw org.springframework.ldap.support.LdapUtils.convertLdapException(e);
                }
            }
        }
    }

    private void closeNamingEnumeration(NamingEnumeration<?> enumeration) {
        try {
            if (enumeration != null) {
                enumeration.close();
            }
        } catch (NamingException e) {
            // Never mind this
        }
    }

    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public void setLdapUserSearch(LdapUserSearch ldapUserSearch) {
        this.ldapUserSearch = ldapUserSearch;
    }

    public void setGroupObjectClass(String groupObjectClass) {
        this.groupObjectClass = groupObjectClass;
    }

    public void setMemberAttribute(String memberAttribute) {
        this.memberAttribute = memberAttribute;
    }

    public void setUsernameAttribute(String usernameAttribute) {
        this.usernameAttribute = usernameAttribute;
    }

    @Autowired(required = false)
    public void setSynchronizationStrategy(LdapUserDetailsSynchronizationStrategy synchronizationStrategy) {
        this.synchronizationStrategy = synchronizationStrategy;
    }
}
