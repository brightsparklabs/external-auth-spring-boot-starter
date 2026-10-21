/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.google.common.collect.Multimap;
import com.google.common.collect.MultimapBuilder;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Enumeration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Extracts the headers from the incoming request so they can be passed to the {@link
 * HeaderFieldsAuthenticationProvider} for the {@code http-headers} authentication method.
 *
 * <p>All request headers are collected into a {@link Multimap} of header name to header values,
 * preserving every value of a repeated header. The multimap is supplied as both the principal and
 * the credentials of an unauthenticated {@link PreAuthenticatedAuthenticationToken}. Deciding which
 * headers identify the user is left to the provider.
 *
 * @author brightSPARK Labs
 */
public class HeaderFieldsAuthenticationConverter implements AuthenticationConverter {

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /** Creates a new converter. The converter is stateless, so a single instance may be shared. */
    public HeaderFieldsAuthenticationConverter() {
        // Nothing to initialise.
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: AuthenticationConverter
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * @return A token holding the request headers, or {@code null} if the container does not allow
     *     access to the headers, in which case authentication is skipped for the request.
     */
    @Override
    public Authentication convert(final HttpServletRequest request) {

        final Enumeration<String> headerNames = request.getHeaderNames();

        // The container does not allow access to the headers, so there is nothing to authenticate.
        if (headerNames == null) {
            return null;
        }

        final Multimap<String, String> headers = MultimapBuilder.hashKeys().hashSetValues().build();

        headerNames
                .asIterator()
                .forEachRemaining(
                        headerName ->
                                headers.putAll(
                                        headerName,
                                        Collections.list(request.getHeaders(headerName))));

        return new PreAuthenticatedAuthenticationToken(headers, headers);
    }
}
