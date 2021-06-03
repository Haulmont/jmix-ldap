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

package io.jmix.autoconfigure.ldap;

import io.jmix.ldap.LdapConfiguration;
import io.jmix.ldap.LdapSecurityConfiguration;
import io.jmix.security.SecurityConfiguration;
import io.jmix.security.StandardSecurityConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@Import({SecurityConfiguration.class, LdapConfiguration.class})
public class LdapAutoConfiguration {

    @EnableWebSecurity
    @ConditionalOnProperty(prefix = "jmix.ldap", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean({StandardSecurityConfiguration.class, LdapSecurityConfiguration.class})
    public static class DefaultLdapSecurityConfiguration extends LdapSecurityConfiguration {
    }
}