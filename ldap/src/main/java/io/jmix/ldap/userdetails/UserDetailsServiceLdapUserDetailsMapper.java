package io.jmix.ldap.userdetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

import java.util.Collection;

/**
 * Maps LDAP user to user details obtained from {@link UserDetailsService}.
 */
public class UserDetailsServiceLdapUserDetailsMapper implements UserDetailsContextMapper {

    protected UserDetailsService userDetailsService;
    protected LdapUserDetailsSynchronizationStrategy synchronizationStrategy;

    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Autowired(required = false)
    public void setSynchronizationStrategy(LdapUserDetailsSynchronizationStrategy synchronizationStrategy) {
        this.synchronizationStrategy = synchronizationStrategy;
    }

    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
                                          Collection<? extends GrantedAuthority> authorities) {
        if (synchronizationStrategy != null) {
            synchronizationStrategy.synchronizeUserDetails(ctx, username, authorities);
        }
        return userDetailsService.loadUserByUsername(username);
    }

    @Override
    public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
        throw new UnsupportedOperationException("JmixLdapUserDetailsMapper only supports reading from a context. Please"
                + " use a subclass if mapUserToContext() is required.");
    }
}
