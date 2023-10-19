/*
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree.
 */

package org.fcrepo.webapp;

import javax.servlet.Filter;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.InvalidRequestFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.fcrepo.auth.common.ContainerRolesPrincipalProvider;
import org.fcrepo.auth.common.DelegateHeaderPrincipalProvider;
import org.fcrepo.auth.common.HttpHeaderPrincipalProvider;
import org.fcrepo.auth.common.PrincipalProvider;
import org.fcrepo.auth.common.ServletContainerAuthFilter;
import org.fcrepo.auth.common.ServletContainerAuthenticatingRealm;
import org.fcrepo.http.api.responses.CorsResponseFilter;
import org.fcrepo.auth.webac.WebACAuthorizingRealm;
import org.fcrepo.auth.webac.WebACFilter;
import org.fcrepo.config.AuthPropsConfig;
import org.fcrepo.config.ConditionOnPropertyTrue;
import org.fcrepo.config.FedoraPropsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

/**
 * Spring config for auth
 *
 * @author pwinckles
 */
@Configuration
@Conditional(AuthConfig.AuthorizationEnabled.class)
public class AuthConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthConfig.class);

    static class AuthorizationEnabled extends ConditionOnPropertyTrue {
        AuthorizationEnabled() {
            super(AuthPropsConfig.FCREPO_AUTH_ENABLED, true);
        }
    }
    static class HeaderPrincipalEnabled extends ConditionOnPropertyTrue {
        HeaderPrincipalEnabled() {
            super(AuthPropsConfig.FCREPO_AUTH_PRINCIPAL_HEADER_ENABLED, false);
        }
    }
    static class RolesPrincipalEnabled extends ConditionOnPropertyTrue {
        RolesPrincipalEnabled() {
            super(AuthPropsConfig.FCREPO_AUTH_PRINCIPAL_ROLES_ENABLED, false);
        }
    }
    static class DelegatePrincipalEnabled extends ConditionOnPropertyTrue {
        DelegatePrincipalEnabled() {
            super(AuthPropsConfig.FCREPO_AUTH_PRINCIPAL_DELEGATE_ENABLED, true);
        }
    }
    static class CorsEnabled extends ConditionOnPropertyTrue {
        CorsEnabled() {
            super(FedoraPropsConfig.FCREPO_CORS_ENABLE_HEADERS, false);
        }
    }

    /**
     * Optional PrincipalProvider filter that will inspect the request header, "some-header", for user role values
     *
     * @param propsConfig config properties
     * @return header principal provider
     */
    @Bean
    @Order(3)
    @Conditional(AuthConfig.HeaderPrincipalEnabled.class)
    public PrincipalProvider headerProvider(final AuthPropsConfig propsConfig) {
        LOGGER.info("Auth header principal provider enabled");
        final var provider = new HttpHeaderPrincipalProvider();
        provider.setHeaderName(propsConfig.getAuthPrincipalHeaderName());
        provider.setSeparator(propsConfig.getAuthPrincipalHeaderSeparator());
        return provider;
    }

    /**
     * Optional PrincipalProvider filter that will use container configured roles as principals
     *
     * @param propsConfig config properties
     * @return roles principal provider
     */
    @Bean
    @Order(4)
    @Conditional(AuthConfig.RolesPrincipalEnabled.class)
    public PrincipalProvider containerRolesProvider(final AuthPropsConfig propsConfig) {
        LOGGER.info("Auth roles principal provider enabled");
        final var provider = new ContainerRolesPrincipalProvider();
        provider.setRoleNames(new HashSet<>(propsConfig.getAuthPrincipalRolesList()));
        return provider;
    }

    /**
     * delegatedPrincipleProvider filter allows a single user to be passed in the header "On-Behalf-Of",
     *            this is to be used as the actor making the request when authenticating.
     *            NOTE: Only users with the role fedoraAdmin can delegate to another user.
     *            NOTE: Only supported in WebAC authentication
     *
     * @return delegate principal provider
     */
    @Bean
    @Order(5)
    @Conditional(AuthConfig.DelegatePrincipalEnabled.class)
    public PrincipalProvider delegatedPrincipalProvider() {
        LOGGER.info("Auth delegate principal provider enabled");
        return new DelegateHeaderPrincipalProvider();
    }

    /**
     * WebAC Authorization Realm
     *
     * @return authorization  realm
     */
    @Bean
    public AuthorizingRealm webACAuthorizingRealm() {
        return new WebACAuthorizingRealm();
    }

    /**
     * Servlet Container Authentication Realm
     *
     * @return authentication realm
     */
    @Bean
    public AuthenticatingRealm servletContainerAuthenticatingRealm() {
        return new ServletContainerAuthenticatingRealm();
    }

    /**
     * @return Security Manager
     */
    @Bean
    public WebSecurityManager securityManager() {
        final var manager = new DefaultWebSecurityManager();
        manager.setRealms(List.of(webACAuthorizingRealm(), servletContainerAuthenticatingRealm()));
        return manager;
    }

    /**
     * Post processor that automatically invokes init() and destroy() methods
     *
     * @return post processor
     */
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    /**
     * @return CORS Response filter
     */
    @Bean
    @Order(1)
    @Conditional(AuthConfig.CorsEnabled.class)
    public Filter corsFilter() {
        return new CorsResponseFilter();
    }

    /**
     * @return Authentication Filter
     */
    @Bean
    @Order(1)
    public Filter servletContainerAuthFilter() {
        return new ServletContainerAuthFilter();
    }

    /**
     * @return Authorization Filter
     */
    @Bean
    @Order(2)
    public Filter webACFilter() {
        return new WebACFilter();
    }

    /**
     * Shiro's filter for rejecting invalid requests
     *
     * @return invalid request filter
     */
    @Bean
    @Order(6)
    public Filter invalidRequest() {
        final var filter = new InvalidRequestFilter();
        filter.setBlockNonAscii(false);
        filter.setBlockBackslash(false);
        filter.setBlockSemicolon(false);
        return filter;
    }

    /**
     * Shiro filter. When defining the filter chain, the Auth filter should come first, followed by 0 or more of the
     * principal provider filters, and finally the webACFilter
     *
     * @param propsConfig config properties
     * @param fedoraPropsConfig fedora config properties
     * @return shiro filter
     */
    @Bean
    @Order(100)
    public ShiroFilterFactoryBean shiroFilter(
            final AuthPropsConfig propsConfig,
            final FedoraPropsConfig fedoraPropsConfig
    ) {
        final var filter = new ShiroFilterFactoryBean();
        filter.setSecurityManager(securityManager());
        final List<String> filterDefinitionsList = new ArrayList<>();
        if (fedoraPropsConfig.isCorsEnabled()) {
            filterDefinitionsList.add("corsFilter");
        }
        filterDefinitionsList.add("servletContainerAuthFilter");
        filterDefinitionsList.addAll(principalProviderChain(propsConfig));
        filterDefinitionsList.add("webACFilter");
        filter.setFilterChainDefinitions("/** = " + String.join(", ", filterDefinitionsList));
        return filter;
    }

    private List<String> principalProviderChain(final AuthPropsConfig propsConfig) {
        final List<String> builder = new ArrayList<>();

        if (propsConfig.isAuthPrincipalHeaderEnabled()) {
            builder.add("headerProvider");
        }
        if (propsConfig.isAuthPrincipalRolesEnabled()) {
            builder.add("containerRolesProvider");
        }
        if (propsConfig.isAuthPrincipalDelegateEnabled()) {
            builder.add("delegatedPrincipalProvider");
        }

        return builder;
    }

}
