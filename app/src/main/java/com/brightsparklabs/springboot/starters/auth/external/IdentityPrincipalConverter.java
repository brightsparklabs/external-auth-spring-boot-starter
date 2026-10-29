/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import java.util.Optional;

/**
 * {@link PrincipalConverter} representing the identity function where the principal is an {@link
 * InternalUser}
 */
public class IdentityPrincipalConverter implements PrincipalConverter<InternalUser> {
    @Override
    public Class<InternalUser> principalType() {
        return InternalUser.class;
    }

    @Override
    public Optional<InternalUser> convertToInternalUser(final InternalUser principal) {
        return Optional.of(principal);
    }

    @Override
    public InternalUser convertToPrincipal(final InternalUser internalUser) {
        return internalUser;
    }
}
