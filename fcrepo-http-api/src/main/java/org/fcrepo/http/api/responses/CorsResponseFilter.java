/*
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree.
 */
package org.fcrepo.http.api.responses;

import static org.fcrepo.http.commons.session.TransactionConstants.ATOMIC_EXPIRES_HEADER;
import static org.fcrepo.http.commons.session.TransactionConstants.ATOMIC_ID_HEADER;
import static org.slf4j.LoggerFactory.getLogger;

import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import java.io.IOException;
import java.util.List;

import org.fcrepo.config.FedoraPropsConfig;
import org.slf4j.Logger;

/**
 * Filter to add Response headers for CORS
 * @author whikloj
 */
@Provider
@PreMatching
public class CorsResponseFilter implements ContainerResponseFilter, ContainerRequestFilter {

    @Inject
    FedoraPropsConfig fedoraPropsConfig;

    private static final Logger LOGGER = getLogger(CorsResponseFilter.class);

    private static final List<String> allowedHeaders = List.of(
            AUTHORIZATION,
            ATOMIC_ID_HEADER,
            ATOMIC_EXPIRES_HEADER,
            "Link"
    );

    @Override
    public void filter(
            final ContainerRequestContext request,
            final ContainerResponseContext response
    ) throws IOException {
        if (fedoraPropsConfig.isCorsEnabled()) {
            response.getHeaders().add("Access-Control-Allow-Origin", fedoraPropsConfig.getCorsAllowedOrigin());
            response.getHeaders().add("Access-Control-Allow-Headers", String.join(",", allowedHeaders));
            response.getHeaders().add("Access-Control-Allow-Credentials", "true");
            response.getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
        }
    }

    @Override
    public void filter(final ContainerRequestContext request) throws IOException {
        if (
                fedoraPropsConfig.isCorsEnabled() &&
                request.getHeaderString("Origin") != null &&
                request.getMethod().equalsIgnoreCase("OPTIONS")
        ) {
            request.abortWith(Response.ok().build());
        }
    }
}
