package io.jmix.ldap;

import io.jmix.core.JmixOrder;
import io.jmix.core.security.event.PreAuthenticationCheckEvent;
import io.jmix.ldap.userdetails.ActiveDirectoryLdapAuthoritiesPopulator;
import io.jmix.ldap.userdetails.JmixLdapGrantedAuthoritiesMapper;
import io.jmix.security.StandardSecurityConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

public class LdapActiveDirectorySecurityConfiguration extends StandardSecurityConfiguration {

    @Autowired
    protected LdapProperties ldapProperties;

    @Autowired
    protected UserDetailsContextMapper ldapUserDetailsContextMapper;

    @Autowired
    protected JmixLdapGrantedAuthoritiesMapper grantedAuthoritiesMapper;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
        auth.authenticationProvider(activeDirectoryAuthenticationProvider());
    }

    AuthenticationProvider activeDirectoryAuthenticationProvider() {
        String urls = StringUtils.join(ldapProperties.getUrls(), StringUtils.SPACE);
        ActiveDirectoryLdapAuthenticationProvider authenticationProvider =
                new ActiveDirectoryLdapAuthenticationProvider(ldapProperties.getActiveDirectoryDomain(), urls);
        authenticationProvider.setConvertSubErrorCodesToExceptions(true);
        authenticationProvider.setUserDetailsContextMapper(ldapUserDetailsContextMapper);
        authenticationProvider.setAuthoritiesMapper(grantedAuthoritiesMapper);
        return authenticationProvider;
    }

    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        return new ActiveDirectoryLdapAuthoritiesPopulator();
    }

    @EventListener
    @Order(JmixOrder.LOWEST_PRECEDENCE - 10)
    public void onPreAuthenticationCheckEvent(PreAuthenticationCheckEvent event) {
        if (!ldapProperties.getStandardAuthenticationUsers().contains(event.getUser().getUsername())) {
            throw new BadCredentialsException("Current user cannot be authenticated via standard authentication");
        }
    }
}
