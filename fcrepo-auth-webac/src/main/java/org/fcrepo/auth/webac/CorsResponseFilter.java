/*
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree.
 */
package org.fcrepo.auth.webac;

import static org.fcrepo.http.commons.session.TransactionConstants.ATOMIC_EXPIRES_HEADER;
import static org.fcrepo.http.commons.session.TransactionConstants.ATOMIC_ID_HEADER;
import static org.slf4j.LoggerFactory.getLogger;

import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static javax.ws.rs.core.HttpHeaders.CONTENT_TYPE;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.fcrepo.config.FedoraPropsConfig;
import org.slf4j.Logger;
import org.springframework.web.filter.RequestContextFilter;

/**
 * Filter to add CORS headers to responses.
 * @author whikloj
 */
public class CorsResponseFilter extends RequestContextFilter {

    private static final Logger LOGGER = getLogger(CorsResponseFilter.class);

    @Inject
    private FedoraPropsConfig fedoraPropsConfig;

    private static final List<String> allowedHeaders = List.of(
            AUTHORIZATION,
            CONTENT_TYPE,
            ATOMIC_ID_HEADER,
            ATOMIC_EXPIRES_HEADER,
            "Link"
    );

    private static List<String> allowedOrigins = new ArrayList<>();

    @PostConstruct
    public void setUp() {
        if (fedoraPropsConfig.getCorsAllowedOrigin().trim().contains(",")) {
            allowedOrigins = Arrays.stream(fedoraPropsConfig.getCorsAllowedOrigin().split(","))
                    .collect(Collectors.toList());
        } else {
            allowedOrigins.add(fedoraPropsConfig.getCorsAllowedOrigin().trim());
        }
    }

    @Override
    protected void doFilterInternal(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final FilterChain filterChain
    ) throws ServletException, IOException {
        if (fedoraPropsConfig.isCorsEnabled()) {
            final String origin = request.getHeader("Origin");
            LOGGER.debug("Received request with Origin header (" + origin + ")");
            if (origin != null) {
                if (allowedOrigins.contains("*")) {
                    response.setHeader("Access-Control-Allow-Origin", "*");
                } else if (allowedOrigins.contains(origin)) {
                    response.setHeader("Access-Control-Allow-Origin", origin);
                    response.addHeader("Vary", "Origin");
                }
                response.setHeader("Access-Control-Allow-Headers", String.join(",", allowedHeaders));
                if (response.getHeader("Access-Control-Allow-Origin") != null &&
                        response.getHeader("Access-Control-Allow-Origin") != "*") {
                    response.setHeader("Access-Control-Allow-Credentials", "true");
                }
                response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
                if (request.getMethod().equalsIgnoreCase("OPTIONS")) {
                    response.setStatus(HttpServletResponse.SC_OK);
                    return;
                }
            }
            filterChain.doFilter(request, response);
        }
    }
}
