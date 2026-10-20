/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import static java.util.Objects.requireNonNull;

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.MdcPrincipalUsernameField;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Adds the authenticated user's username to the SLF4J MDC for the duration of the request, so it
 * can be logged as part of auditing.
 *
 * <p>Must be registered after the authentication filter so the {@link SecurityContextHolder} is
 * already populated.
 *
 * @param <P> The type of principal stored in the {@link Authentication}.
 */
public class AddUserAuthToRequestFilter<P> extends OncePerRequestFilter {

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Type of principal the converter accepts, used to guard the cast. */
    private final Class<P> principalType;

    /** Converts the system principal to an {@link InternalUser}. */
    private final PrincipalConverter<P> principalConverter;

    /** MDC key to store the authenticated user's username against. */
    private final String mdcUsernameField;

    /** The field in the {@link InternalUser} to insert into the MDC request. */
    private final MdcPrincipalUsernameField principalUsernameField;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a new filter.
     *
     * @param principalType Type of principal the converter accepts.
     * @param principalConverter Converts the system principal to an {@link InternalUser}.
     * @param mdcUsernameField MDC key to store the authenticated user's username against.
     * @param principalUsernameField The field in the {@link InternalUser} to insert into the MDC
     *     request.
     */
    public AddUserAuthToRequestFilter(
            final Class<P> principalType,
            final PrincipalConverter<P> principalConverter,
            final String mdcUsernameField,
            final MdcPrincipalUsernameField principalUsernameField) {
        this.principalType = requireNonNull(principalType);
        this.principalConverter = requireNonNull(principalConverter);
        this.mdcUsernameField = requireNonNull(mdcUsernameField);
        this.principalUsernameField = requireNonNull(principalUsernameField);
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: OncePerRequestFilter
    // -------------------------------------------------------------------------

    @Override
    protected void doFilterInternal(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final FilterChain filterChain)
            throws ServletException, IOException {
        final Optional<String> username = resolveUsername();
        username.ifPresent(name -> MDC.put(mdcUsernameField, name));
        try {
            filterChain.doFilter(request, response);
        } finally {
            // Always clear, as servlet threads are pooled and reused across requests.
            MDC.remove(mdcUsernameField);
        }
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Resolves the username of the authenticated user, if any.
     *
     * @return The username, or empty if the request is unauthenticated or the principal is not of
     *     the expected type.
     */
    private Optional<String> resolveUsername() {
        final Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }

        // Anonymous requests carry a String principal, so guard the cast.
        final Object principal = authentication.getPrincipal();
        if (!principalType.isInstance(principal)) {
            return Optional.empty();
        }

        return principalConverter
                .convertToInternalUser(principalType.cast(principal))
                .map(user -> user.getPrincipalUsername(principalUsernameField));
    }
}
