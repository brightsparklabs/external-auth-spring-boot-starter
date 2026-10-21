/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.HttpHeadersConfiguration;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multimap;
import com.google.common.collect.MultimapBuilder;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.stream.Stream;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Extracts the identity headers from the incoming request so they can be passed to the {@link
 * HeaderFieldsAuthenticationProvider} for the {@code http-headers} authentication method.
 *
 * <p>Only the headers named in the {@link HttpHeadersConfiguration} are collected (matched
 * case-insensitively), into a {@link Multimap} of header name to header values. Every value of a
 * repeated header is kept, in the order received. The multimap is supplied as both the principal
 * and the credentials of an unauthenticated {@link PreAuthenticatedAuthenticationToken}.
 *
 * <p>Restricting the collected headers keeps unrelated and sensitive headers (e.g. {@code
 * Authorization} and {@code Cookie}) out of the token, which may be logged or published in
 * authentication failure events.
 *
 * @author brightSPARK Labs
 */
public class HeaderFieldsAuthenticationConverter implements AuthenticationConverter {

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Names of the headers to collect, compared case-insensitively. */
    private final ImmutableSet<String> identityHeaderNames;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a new converter.
     *
     * @param configuration The configured header names, which determine the headers collected.
     */
    public HeaderFieldsAuthenticationConverter(final HttpHeadersConfiguration configuration) {
        this.identityHeaderNames =
                Stream.of(
                                configuration.usernameHeaderFields(),
                                configuration.firstNameHeaderFields(),
                                configuration.lastNameHeaderFields(),
                                configuration.emailHeaderFields(),
                                configuration.groupsHeaderFields(),
                                configuration.rolesHeaderFields())
                        .flatMap(Collection::stream)
                        .map(header -> header.toLowerCase(Locale.ROOT))
                        .collect(ImmutableSet.toImmutableSet());
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: AuthenticationConverter
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * @return A token holding the identity headers (possibly none), or {@code null} if the
     *     container does not allow access to the headers, in which case authentication is skipped
     *     for the request.
     */
    @Override
    public Authentication convert(final HttpServletRequest request) {

        final Enumeration<String> headerNames = request.getHeaderNames();

        // The container does not allow access to the headers, so there is nothing to authenticate.
        if (headerNames == null) {
            return null;
        }

        final Multimap<String, String> headers =
                MultimapBuilder.linkedHashKeys().arrayListValues().build();

        headerNames
                .asIterator()
                .forEachRemaining(
                        headerName -> {
                            // Convert to lower case for case insensitivity.
                            final String lowercaseHeaderName = headerName.toLowerCase(Locale.ROOT);
                            if (identityHeaderNames.contains(lowercaseHeaderName)) {
                                headers.putAll(
                                        lowercaseHeaderName,
                                        Collections.list(request.getHeaders(headerName)));
                            }
                        });

        return new PreAuthenticatedAuthenticationToken(headers, headers);
    }
}
