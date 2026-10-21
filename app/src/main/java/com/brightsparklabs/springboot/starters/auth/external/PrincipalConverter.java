/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import jakarta.validation.constraints.NotNull;
import java.security.Principal;
import java.util.Optional;
import org.springframework.security.core.AuthenticatedPrincipal;

/**
 * Interface for converting between {@link InternalUser} and the {@link Principal} used in the
 * system.
 *
 * @param <P> The {@link AuthenticatedPrincipal} type to convert
 */
public interface PrincipalConverter<P extends AuthenticatedPrincipal> {
    /**
     * Returns the type of principal this converter produces and accepts.
     *
     * <p>Used to check a principal's type before it is passed to {@link #convertToInternalUser}.
     *
     * @return The principal type.
     */
    Class<P> principalType();

    /**
     * Convert the principal {@link P} to an {@link InternalUser}.
     *
     * @param principal principal to convert
     * @return the optionally converted {@link InternalUser}, or {@link Optional#empty()} if the
     *     conversion cannot be done.
     */
    Optional<InternalUser> convertToInternalUser(P principal);

    /**
     * Convert an arbitrary principal to an {@link InternalUser}, guarding against principals which
     * are not of the type handled by this converter.
     *
     * <p>Useful where the principal is sourced from an {@code Authentication}, as anonymous or
     * foreign authentications carry principals of other types (e.g. a {@code String}).
     *
     * @param principal principal to convert, may be {@code null}
     * @return the optionally converted {@link InternalUser}, or {@link Optional#empty()} if the
     *     principal is not of type {@link P} or the conversion cannot be done.
     */
    default Optional<InternalUser> toInternalUser(final Object principal) {
        final Class<P> type = principalType();
        if (!type.isInstance(principal)) {
            return Optional.empty();
        }
        return convertToInternalUser(type.cast(principal));
    }

    /**
     * Convert the principal {@link InternalUser} to an {@link P}.
     *
     * @param internalUser internal user to convert
     * @return the converted {@link P}
     */
    @NotNull
    P convertToPrincipal(InternalUser internalUser);
}
