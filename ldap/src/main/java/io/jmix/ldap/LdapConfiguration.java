/*
 * Copyright 2020 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jmix.ldap;

import io.jmix.core.CoreConfiguration;
import io.jmix.core.annotation.JmixModule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

@Configuration
@ComponentScan
@ConfigurationPropertiesScan
@JmixModule(dependsOn = CoreConfiguration.class)
@PropertySource(name = "io.jmix.ldap", value = "classpath:/io/jmix/ldap/module.properties")
public class LdapConfiguration {
    @Autowired
    protected LdapProperties ldapProperties;

    @Bean
    LdapContextSource ldapContextSource() {
        DefaultSpringSecurityContextSource contextSource =
                new DefaultSpringSecurityContextSource(ldapProperties.getUrls(), ldapProperties.getBaseDn());
        contextSource.setUserDn(ldapProperties.getManagerDn());
        contextSource.setPassword(ldapProperties.getManagerPassword());
        return contextSource;
    }

    @Bean
    UserDetailsContextMapper ldapUserDetailsMapper() {
        if (ldapProperties.isUseInternalUserDetailsService()) {
            return new UserDetailsServiceLdapUserDetailsMapper();
        } else {
            return new LdapUserDetailsMapper();
        }
    }

    @Bean
    JmixLdapGrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        JmixLdapGrantedAuthoritiesMapper authoritiesMapper = new JmixLdapGrantedAuthoritiesMapper();
        authoritiesMapper.setDefaultRoles(ldapProperties.getDefaultRoles());
        return authoritiesMapper;
    }

    @Bean
    LdapTemplate ldapTemplate() {
        return new LdapTemplate(ldapContextSource());
    }
}
