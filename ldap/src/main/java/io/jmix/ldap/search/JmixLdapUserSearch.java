package io.jmix.ldap.search;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.ldap.search.LdapUserSearch;

import java.util.Set;

public interface JmixLdapUserSearch extends LdapUserSearch {
    Set<DirContextOperations> searchForUsersBySubstring(String substring);
}
