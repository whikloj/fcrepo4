/*
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree.
 */

package org.fcrepo.webapp;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.fcrepo.config.AuthPropsConfig;
import org.fcrepo.config.ConditionOnPropertyFalse;
import org.fcrepo.config.FedoraPropsConfig;
import org.fcrepo.http.api.responses.CorsResponseFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Spring auth config when authorization is disabled
 *
 * @author pwinckles
 */
@Configuration
@Conditional(NoAuthConfig.AuthorizationDisabled.class)
public class NoAuthConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(NoAuthConfig.class);

    static class AuthorizationDisabled extends ConditionOnPropertyFalse {
        AuthorizationDisabled() {
            super(AuthPropsConfig.FCREPO_AUTH_ENABLED, true);
        }
    }

    /**
     * This bean returns a no-op shiro filter when authorization is disabled.
     *
     * @param fedoraPropsConfig Fedora properties.
     * @return no-op shiro filter
     */
    @Bean
    public Filter shiroFilter(final FedoraPropsConfig fedoraPropsConfig) {
        LOGGER.info("Authorization is disabled");
        if (fedoraPropsConfig.isCorsEnabled()) {
            return new CorsResponseFilter();
        } else {
            return new OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(final HttpServletRequest httpServletRequest,
                                                final HttpServletResponse httpServletResponse,
                                                final FilterChain filterChain) throws ServletException, IOException {
                    filterChain.doFilter(httpServletRequest, httpServletResponse);
                }
            };
        }
    }

}
