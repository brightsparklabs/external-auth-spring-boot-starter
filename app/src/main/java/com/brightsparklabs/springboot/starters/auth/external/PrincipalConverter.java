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

/**
 * Interface for converting between {@link InternalUser} and the {@link Principal} used in the
 * system.
 *
 * @param <P> The {@link Principal} type to convert
 */
public interface PrincipalConverter<P> {
    /**
     * Convert the principal {@link P} to an {@link InternalUser}.
     *
     * @param principal principal to convert
     * @return the optionally converted {@link InternalUser}, or {@link Optional#empty()} if the
     *     conversion cannot be done.
     */
    Optional<InternalUser> convertToInternalUser(P principal);

    /**
     * Convert the principal {@link InternalUser} to an {@link P}.
     *
     * @param internalUser internal user to convert
     * @return the converted {@link P}
     */
    @NotNull
    P convertToPrincipal(InternalUser internalUser);
}
