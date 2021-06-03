package io.jmix.ldap;

import io.jmix.core.UnconstrainedDataManager;
import io.jmix.core.entity.EntityValues;
import io.jmix.core.security.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

public abstract class AbstractLdapUserDetailsSynchronizationStrategy<T extends UserDetails>
        implements LdapUserDetailsSynchronizationStrategy {

    private static final Logger log = LoggerFactory.getLogger(AbstractLdapUserDetailsSynchronizationStrategy.class);

    @Autowired
    private UnconstrainedDataManager dataManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JmixLdapGrantedAuthoritiesMapper authoritiesMapper;

    @Override
    public UserDetails synchronizeUserDetails(DirContextOperations ctx, String username,
                                              Collection<? extends GrantedAuthority> authorities) {
        UserDetails jmixUserDetails;
        try {
            jmixUserDetails = userRepository.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            log.info("User with login {} wasn't found in user repository", username);
            jmixUserDetails = createUserDetails(username);
        }

        //copy ldap attributes to UserDetails
        mapUserDetailsAttributes(jmixUserDetails, ctx);

        //obtain user roles
        Set<GrantedAuthority> grantedAuthorities = authoritiesMapper.mapAuthorities(authorities);
        grantedAuthorities.addAll(getAdditionalRoles(ctx, username));

        //persist user details and roles if needed
        dataManager.save(jmixUserDetails);
        //todo store roles if needed

        return jmixUserDetails;
    }

    protected abstract Class<T> getUserClass();

    protected T createUserDetails(String username) {
        T userDetails = dataManager.create(getUserClass());
        EntityValues.setValue(userDetails, "username", username);
        return userDetails;
    }

    protected void mapUserDetailsAttributes(UserDetails userDetails, DirContextOperations ctx) {
        EntityValues.setValue(userDetails, "lastName", ctx.getStringAttribute("sn"));
        EntityValues.setValue(userDetails, "email", ctx.getStringAttribute("mail"));
    }

    /**
     * This method should be overridden if required to obtain any additional roles for the
     * given user (on top of those obtained from the users groups).
     * @param user the context representing the user who's roles are required
     * @return the extra roles which will be merged with those returned by the group search
     */
    protected Set<GrantedAuthority> getAdditionalRoles(DirContextOperations user, String username) {
        return Collections.emptySet();
    }
}
