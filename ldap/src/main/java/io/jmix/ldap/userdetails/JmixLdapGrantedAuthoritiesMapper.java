/*
 * Copyright 2021 Haulmont.
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

package io.jmix.ldap.userdetails;

import io.jmix.security.authentication.RoleGrantedAuthority;
import io.jmix.security.model.ResourceRole;
import io.jmix.security.model.RowLevelRole;
import io.jmix.security.role.ResourceRoleRepository;
import io.jmix.security.role.RowLevelRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.util.Assert;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * GrantedAuthoritiesMapper that maps authorities to {@link RoleGrantedAuthority}s.
 * <p>
 * First, it tries to find a resource role with the same code. If it haven't been found,
 * it searches for a row-level role with the same code.
 */
public class JmixLdapGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

    private ResourceRoleRepository resourceRoleRepository;
    private RowLevelRoleRepository rowLevelRoleRepository;

    private List<String> defaultRoles;
    private Function<String, Collection<String>> authorityToRoleCodesMapper;

    @Autowired
    public void setResourceRoleRepository(ResourceRoleRepository resourceRoleRepository) {
        this.resourceRoleRepository = resourceRoleRepository;
    }

    @Autowired
    public void setRowLevelRoleRepository(RowLevelRoleRepository rowLevelRoleRepository) {
        this.rowLevelRoleRepository = rowLevelRoleRepository;
    }

    @Override
    public Set<GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        HashSet<GrantedAuthority> mapped = new HashSet<>(authorities.size());
        for (GrantedAuthority authority : authorities) {
            if (authority instanceof RoleGrantedAuthority) {
                mapped.add(authority);
            } else {
                mapped.addAll(mapAuthority(authority.getAuthority()));
            }
        }
        if (this.defaultRoles != null) {
            List<GrantedAuthority> defaultAuthorities = this.defaultRoles.stream()
                    .map(this::mapAuthority)
                    .flatMap(Collection::stream)
                    .collect(Collectors.toList());
            mapped.addAll(defaultAuthorities);
        }
        return mapped;
    }

    protected List<GrantedAuthority> mapAuthority(String authority) {
        Collection<String> roleCodes = new HashSet<>();
        roleCodes.add(authority);
        if (authorityToRoleCodesMapper != null) {
            roleCodes.addAll(authorityToRoleCodesMapper.apply(authority));
        }

        return roleCodes.stream()
                .map(roleCode -> {
                    GrantedAuthority grantedAuthority = null;
                    ResourceRole resourceRole = resourceRoleRepository.findRoleByCode(roleCode);
                    if (resourceRole != null) {
                        grantedAuthority = RoleGrantedAuthority.ofResourceRole(resourceRole);
                    } else {
                        RowLevelRole rowLevelRole = rowLevelRoleRepository.findRoleByCode(roleCode);
                        if (rowLevelRole != null) {
                            grantedAuthority = RoleGrantedAuthority.ofRowLevelRole(rowLevelRole);
                        }
                    }
                    return grantedAuthority;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public void setDefaultRoles(List<String> roles) {
        Assert.notNull(roles, "roles list cannot be null");
        this.defaultRoles = roles;
    }

    /**
     * Sets the mapping function which will be used to convert an authority name
     * to collection of role codes which will be used to obtain a resource or row-level roles.
     *
     * @param authorityToRoleCodesMapper the mapping function
     */
    @SuppressWarnings("unused")
    public void setAuthorityToRoleCodesMapper(Function<String, Collection<String>> authorityToRoleCodesMapper) {
        this.authorityToRoleCodesMapper = authorityToRoleCodesMapper;
    }
}
