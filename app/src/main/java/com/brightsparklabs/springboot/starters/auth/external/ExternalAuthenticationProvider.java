/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import static java.util.Objects.requireNonNull;

import com.google.common.collect.ImmutableSet;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Template-method base for authenticating users based on information passed by an external
 * authentication provider.
 *
 * <p>Subclasses implement {@link #doAuthenticate(Object)}. This base converts the resulting {@link
 * InternalUser} to the system principal and translates failures into Spring Security exceptions:
 *
 * <ul>
 *   <li>{@link AuthenticationDeniedException} is rethrown as a {@link BadCredentialsException}
 *       wrapping the original, so other providers may still be tried.
 *   <li>{@link AuthenticationServiceException} is propagated as-is.
 * </ul>
 *
 * <p>Listeners are not notified here. Spring Security publishes an event for each outcome, which
 * the {@link AuthenticationEventListenerDispatcher} forwards to the registered {@link
 * AuthenticationEventListener} beans.
 *
 * @author brightSPARK Labs
 */
public abstract class ExternalAuthenticationProvider implements AuthenticationProvider {

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Converter between {@link InternalUser} and the system principal. */
    private final PrincipalConverter<?> principalConverter;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a new provider.
     *
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     */
    protected ExternalAuthenticationProvider(final PrincipalConverter<?> principalConverter) {
        this.principalConverter = requireNonNull(principalConverter);
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: AuthenticationProvider
    // -------------------------------------------------------------------------

    @Override
    public Authentication authenticate(final Authentication authentication)
            throws AuthenticationException {
        final InternalUser user;
        try {
            user = doAuthenticate(authentication.getCredentials());
        } catch (final AuthenticationDeniedException denied) {
            throw new BadCredentialsException(denied.getMessage(), denied);
        }

        return new PreAuthenticatedAuthenticationToken(
                principalConverter.convertToPrincipal(user),
                authentication.getCredentials(),
                toAuthorities(user));
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
    }

    // -------------------------------------------------------------------------
    // PROTECTED METHODS
    // -------------------------------------------------------------------------

    /**
     * Authenticates a user based on the credentials provided.
     *
     * @param credentials The credentials used to authenticate the user.
     * @return The authenticated internal user.
     * @throws AuthenticationDeniedException When the credentials are invalid (denial).
     * @throws AuthenticationServiceException When the authenticator cannot verify the credentials
     *     (hard error).
     */
    protected abstract InternalUser doAuthenticate(Object credentials)
            throws AuthenticationDeniedException;

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Derives Spring authorities from the user's roles.
     *
     * @param user The user to derive the authorities from.
     * @return The authorities for the user.
     */
    private static ImmutableSet<GrantedAuthority> toAuthorities(final InternalUser user) {
        return user.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(ImmutableSet.toImmutableSet());
    }
}
