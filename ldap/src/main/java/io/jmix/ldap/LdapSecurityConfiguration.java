package io.jmix.ldap;

import io.jmix.security.StandardSecurityConfiguration;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

public class LdapSecurityConfiguration extends StandardSecurityConfiguration {

    @Autowired
    protected LdapProperties ldapProperties;

    @Autowired
    protected LdapContextSource ldapContextSource;

    @Autowired
    protected UserDetailsContextMapper ldapUserDetailsContextMapper;

    @Autowired
    protected JmixLdapGrantedAuthoritiesMapper grantedAuthoritiesMapper;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
        addLdapAuthenticationProvider(auth);
    }

    protected void addLdapAuthenticationProvider(AuthenticationManagerBuilder auth) throws Exception {
        auth.ldapAuthentication()
                .contextSource(ldapContextSource)
                .userSearchBase(ldapProperties.getUserSearchBase())
                .userSearchFilter(ldapProperties.getUserSearchFilter())
                .ldapAuthoritiesPopulator(ldapAuthoritiesPopulator())
                .rolePrefix(StringUtils.EMPTY)
                .userDetailsContextMapper(ldapUserDetailsContextMapper)
                .authoritiesMapper(grantedAuthoritiesMapper);
    }

    LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        DefaultLdapAuthoritiesPopulator authoritiesPopulator =
                new DefaultLdapAuthoritiesPopulator(ldapContextSource, ldapProperties.getGroupSearchBase());
        authoritiesPopulator.setGroupSearchFilter(ldapProperties.getGroupSearchFilter());
        authoritiesPopulator.setSearchSubtree(ldapProperties.isGroupSearchSubtree());
        authoritiesPopulator.setGroupRoleAttribute(ldapProperties.getGroupRoleAttribute());
        authoritiesPopulator.setConvertToUpperCase(false);
        return authoritiesPopulator;
    }

//    @Bean
//    LdapAuthenticationProvider ldapAuthenticationProvider() {
//        BindAuthenticator authenticator = new BindAuthenticator(ldapContextSource());
//        authenticator.setUserDnPatterns(new String[]{environment.getProperty("ldap.user.dn.pattern")});
//        LdapAuthenticationProvider ldapAuthenticationProvider =
//                new LdapAuthenticationProvider(authenticator, ldapAuthoritiesPopulator());

//        ldapAuthenticationProvider.setUserDetailsContextMapper(ldapUserDetailsMapper());
//        return ldapAuthenticationProvider;
    //    }
//    }
}
