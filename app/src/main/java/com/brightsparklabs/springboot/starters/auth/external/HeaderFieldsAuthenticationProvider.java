/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.HttpHeadersConfiguration;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multimap;
import java.util.Collection;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.springframework.security.authentication.BadCredentialsException;

/**
 * Authenticates users from HTTP headers set by an upstream authenticating proxy (e.g.
 * oauth2-proxy), for the {@code http-headers} authentication method.
 *
 * <p>Expects the credentials to be the header multimap produced by {@link
 * HeaderFieldsAuthenticationConverter}. Header names are matched case-insensitively, as HTTP
 * requires. Each user field is read from the first configured header (in priority order, as set in
 * {@link HttpHeadersConfiguration}) that is present with a non-empty value:
 *
 * <ul>
 *   <li>The username, first name, and last name are required. If any is missing, authentication is
 *       denied.
 *   <li>The email is optional.
 *   <li>Groups and roles are optional. They are read from the first header which is present, with
 *       each value split on commas.
 * </ul>
 *
 * <p>IMPORTANT: This method trusts the headers implicitly. The application must only be reachable
 * via the authenticating proxy, which must strip any client-supplied values for these headers.
 *
 * @author brightSPARK Labs
 */
public class HeaderFieldsAuthenticationProvider extends ExternalAuthenticationProvider {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** Splits comma-separated header values, trimming whitespace and dropping empty entries. */
    private static final Splitter SPLIT_ON_COMMAS =
            Splitter.on(',').omitEmptyStrings().trimResults();

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** The candidate header names to read each user field from. */
    private final HttpHeadersConfiguration configuration;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a new provider.
     *
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     * @param configuration The candidate header names to read each user field from.
     */
    public HeaderFieldsAuthenticationProvider(
            final PrincipalConverter<?> principalConverter,
            final HttpHeadersConfiguration configuration) {
        super(principalConverter);
        this.configuration = configuration;
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: ExternalAuthenticationProvider
    // -------------------------------------------------------------------------

    /**
     * Builds the user from the request headers.
     *
     * @param credentials The header multimap produced by {@link
     *     HeaderFieldsAuthenticationConverter}.
     * @return The user described by the headers.
     * @throws BadCredentialsException If the credentials are not a header multimap, or a required
     *     field is missing from the headers.
     */
    @Override
    public InternalUser doAuthenticate(final Object credentials) {
        if (!(credentials instanceof Multimap<?, ?>)) {
            throw new BadCredentialsException("No header fields provided to authenticator");
        }

        // Checked above.
        @SuppressWarnings("unchecked")
        final Multimap<String, String> headers = (Multimap<String, String>) credentials;

        try {

            return new InternalUser(
                    extractHeaderValue(configuration.usernameHeaderFields(), headers, "username"),
                    extractHeaderValue(
                            configuration.firstNameHeaderFields(), headers, "first name"),
                    extractHeaderValue(configuration.lastNameHeaderFields(), headers, "last name"),
                    extractOptionalHeaderValue(configuration.emailHeaderFields(), headers),
                    extractHeaderValues(configuration.groupsHeaderFields(), headers),
                    extractHeaderValues(configuration.rolesHeaderFields(), headers),
                    Optional.empty());

        } catch (final IllegalArgumentException ex) {
            throw new BadCredentialsException(ex.getMessage(), ex);
        }
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Extracts a required single value from the first candidate header present with a non-empty
     * value.
     *
     * <p>HTTP header names are case-insensitive, and HTTP/2 and some proxies send them in lower
     * case, so the configured names must match regardless of case. Values of headers whose names
     * differ only in case are merged, as HTTP treats them as the same header.
     *
     * @param headerNames The candidate header names, in priority order.
     * @param headers The request headers.
     * @param field Human-readable name of the field being extracted, used in the error message.
     * @return The first value of the first matching header.
     * @throws IllegalArgumentException If none of the candidate headers has a non-empty value.
     */
    private String extractHeaderValue(
            final Collection<String> headerNames,
            final Multimap<String, String> headers,
            final String field)
            throws IllegalArgumentException {

        for (final String headerName : headerNames) {
            final Optional<String> result =
                    headers.get(headerName.toLowerCase(Locale.ROOT)).stream().findFirst();
            if (result.isEmpty() || result.get().isEmpty()) {
                continue;
            }

            return result.get();
        }

        throw new IllegalArgumentException(
                "Request headers did not contain a valid ["
                        + field
                        + "] value under configured header names "
                        + headerNames);
    }

    /**
     * Extracts an optional single value from the first candidate header present with a non-empty
     * value.
     *
     * <p>HTTP header names are case-insensitive, and HTTP/2 and some proxies send them in lower
     * case, so the configured names must match regardless of case. Values of headers whose names
     * differ only in case are merged, as HTTP treats them as the same header.
     *
     * @param headerNames The candidate header names, in priority order.
     * @param headers The request headers.
     * @return The first value of the first matching header, or {@link Optional#empty()} if none of
     *     the candidate headers has a non-empty value.
     */
    private Optional<String> extractOptionalHeaderValue(
            final Collection<String> headerNames, final Multimap<String, String> headers)
            throws IllegalArgumentException {

        for (final String headerName : headerNames) {
            final Optional<String> result =
                    headers.get(headerName.toLowerCase(Locale.ROOT)).stream().findFirst();
            if (result.isEmpty() || result.get().isEmpty()) {
                continue;
            }

            return result;
        }

        return Optional.empty();
    }

    /**
     * Extracts a set of values from the first candidate header which is present.
     *
     * <p>HTTP header names are case-insensitive, and HTTP/2 and some proxies send them in lower
     * case, so the configured names must match regardless of case. Values of headers whose names
     * differ only in case are merged, as HTTP treats them as the same header.
     *
     * <p>Every value of a repeated header is included, and each value is split on commas. Headers
     * further down the priority order are not consulted once a match is found.
     *
     * @param headerNames The candidate header names, in priority order.
     * @param headers The request headers.
     * @return The distinct values, or an empty set if none of the candidate headers is present.
     */
    private ImmutableSet<String> extractHeaderValues(
            final Collection<String> headerNames, final Multimap<String, String> headers)
            throws IllegalArgumentException {

        Stream<String> values = Stream.empty();

        for (final String headerName : headerNames) {
            final Collection<String> value = headers.get(headerName.toLowerCase(Locale.ROOT));
            if (!value.isEmpty()) {
                values = value.stream();
                break;
            }
        }

        return values.map(SPLIT_ON_COMMAS::split)
                .flatMap(x -> StreamSupport.stream(x.spliterator(), false))
                .collect(ImmutableSet.toImmutableSet());
    }
}
