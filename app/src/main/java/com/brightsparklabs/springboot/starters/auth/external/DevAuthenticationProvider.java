/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authentication provider which always returns the User from configuration. For use during
 * development only
 *
 * @author brightSPARK Labs
 */
public class DevAuthenticationProvider extends ExternalAuthenticationProvider {
    // -------------------------------------------------------------------------
    // CLASS VARIABLES
    // -------------------------------------------------------------------------

    /** Class logger. */
    private static final Logger logger = LoggerFactory.getLogger(DevAuthenticationProvider.class);

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** The fixed user to return, bound from `brightsparklabs.auth.user`. */
    private final InternalUser user;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Default constructor.
     *
     * @param principalConverter Converter between InternalUser and the system principal.
     * @param user The fixed user to return, bound from `brightsparklabs.auth.user`.
     */
    public DevAuthenticationProvider(
            final PrincipalConverter<?> principalConverter, final InternalUser user) {
        super(principalConverter);
        this.user = user;
    }

    // -------------------------------------------------------------------------
    // Implementation: ExternalAuthenticationProvider
    // -------------------------------------------------------------------------

    @Override
    public InternalUser doAuthenticate(final Object credentials) {
        logger.warn("********** USING DEV MODE AUTHENTICATOR. DO NOT USE IN PRODUCTION **********");
        return user;
    }
}
