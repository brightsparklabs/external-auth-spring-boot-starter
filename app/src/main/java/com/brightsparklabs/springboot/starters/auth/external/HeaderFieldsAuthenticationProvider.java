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

// spotless:off - NOTE: Spotless does not support {@snippet} annotations.
/**
 * Authenticates users from HTTP headers set by an upstream authenticating proxy (e.g.
 * oauth2-proxy), for the {@code http-headers} authentication method.
 *
 * <p>IMPORTANT: This method trusts the headers implicitly. The application must only be reachable
 * via the authenticating proxy, which must strip any client-supplied values for these headers.
 *
 * <p>The method expects the credentials to be the header multimap produced by {@link
 * HeaderFieldsAuthenticationConverter}. Header names are matched case-insensitively, as HTTP
 * requires. Each user field is read from the first configured header (in priority order, as set in
 * {@link HttpHeadersConfiguration}) that is present with a non-empty value:
 *
 * <ul>
 *   <li>The username, first name, and last name are required. If any is missing, authentication is
 *       denied.
 *   <li>The email is optional.
 *   <li>Groups and roles are optional. They are read from the first header of a given type which is
 *       present, with each value split on commas. If the same header is provided multiple times
 *       with different values, each unique values will also be added.
 * </ul>
 *
 * <p>E.g. given the following headers configuration:
 *
 * {@snippet lang=yaml :
 *     headers:
 *       username-header-fields:
 *         - "X-Auth-Request-Preferred-Username"
 *         - "X-Forwarded-Preferred-Username"
 *         - "X-Auth-Username"
 *       first-name-header-fields:
 *         - "X-Auth-Request-Given-Name"
 *         - "X-Forwarded-Given-Name"
 *         - "X-Auth-Given-Name"
 *       last-name-header-fields:
 *         - "X-Auth-Request-Family-Name"
 *         - "X-Forwarded-Family-Name"
 *         - "X-Auth-Family-Name"
 *       email-header-fields:
 *         - "X-Auth-Request-Email"
 *         - "X-Forwarded-Email"
 *         - "X-Auth-Email"
 *       groups-header-fields:
 *         - "X-Auth-Request-Groups"
 *         - "X-Forwarded-Groups"
 *         - "X-Auth-Groups"
 *       roles-header-fields:
 *         - "X-Auth-Request-Roles"
 *         - "X-Forwarded-Roles"
 *         - "X-Auth-Roles"
 * }
 *
 * <p>If the following request were received:
 *
 * <pre>
 *     curl -H 'X-Auth-Username: test.user' \
 *       -H 'X-Auth-Request-Given-Name: test' \
 *       -H 'X-Auth-Given-Name: foo' \
 *       -H 'X-Auth-Request-Family-Name: user' \
 *       -H 'X-Auth-Request-Family-Name: bar' \
 *       -H 'X-Auth-Roles: ROLE_1,ROLE_2' \
 *       -H 'X-Auth-Roles: ROLE_3' \
 *       -H 'X-Auth-Request-Groups: GROUP_1' \
 *       -H 'X-Auth-Request-Groups: GROUP_2' \
 *       -H 'X-Auth-Groups: ANOTHER' \
 *     localhost:8080/api/me
 * </pre>
 *
 * <p>Then the following user principal would be created:
 *
 * {@snippet lang=yaml :
 *     user:
 *       # NOTE: 'test' used over 'foo' because of the configured header priority.
 *       first-name: test
 *       # NOTE: 'user' used over 'bar' as the former was declared first.
 *       last-name: user
 *       username: test.user
 *       # NOTE: Email is missing as it wasn't provided.
 *       # NOTE: 'ANOTHER' is excluded from the groups list due to being provided via a different, lower priority header.
 *       groups:
 *         - GROUP_1
 *         - GROUP_2
 *       # NOTE: Roles are populated via comma-separated values and a second header value.
 *       roles:
 *         - ROLE_1
 *         - ROLE_2
 *         - ROLE_3
 * }
 *
 * @author brightSPARK Labs
 */
// spotless:on - NOTE: Spotless does not support {@snippet} annotations.
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
                    extractHeaderFirstValue(
                            configuration.usernameHeaderFields(), headers, "username"),
                    extractHeaderFirstValue(
                            configuration.firstNameHeaderFields(), headers, "first name"),
                    extractHeaderFirstValue(
                            configuration.lastNameHeaderFields(), headers, "last name"),
                    extractOptionalHeaderFirstValue(configuration.emailHeaderFields(), headers),
                    extractHeaderAllValues(configuration.groupsHeaderFields(), headers),
                    extractHeaderAllValues(configuration.rolesHeaderFields(), headers),
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
    private String extractHeaderFirstValue(
            final Collection<String> headerNames,
            final Multimap<String, String> headers,
            final String field)
            throws IllegalArgumentException {

        return headerNames.stream()
                // NOTE: Ensure the Locale is consistent with those used in the
                // HeaderFieldsAuthenticationConverter.
                .map(header -> headers.get(header.toLowerCase(Locale.ROOT)))
                .flatMap(Collection::stream)
                .filter(value -> !value.isEmpty())
                .findFirst()
                .orElseThrow(
                        () ->
                                new IllegalArgumentException(
                                        "Request headers did not contain a valid `"
                                                + field
                                                + "` value under configured header names "
                                                + headerNames));
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
    private Optional<String> extractOptionalHeaderFirstValue(
            final Collection<String> headerNames, final Multimap<String, String> headers)
            throws IllegalArgumentException {

        return headerNames.stream()
                // NOTE: Ensure the Locale is consistent with those used in the
                // HeaderFieldsAuthenticationConverter.
                .map(header -> headers.get(header.toLowerCase(Locale.ROOT)))
                .flatMap(Collection::stream)
                .filter(value -> !value.isEmpty())
                .findFirst();
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
    private ImmutableSet<String> extractHeaderAllValues(
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
