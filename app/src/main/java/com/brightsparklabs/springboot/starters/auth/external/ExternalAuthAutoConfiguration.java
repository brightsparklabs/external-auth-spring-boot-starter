/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for the externally authenticated auth starter.
 *
 * <p>Wires the beans required to authenticate users whose principal is supplied by an external
 * source, such as OAuth2 headers.
 *
 * @author brightSPARK Labs
 */
public class ExternalAuthAutoConfiguration {
    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // CLASS VARIABLES
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    // Default principle converter, can be overwritten by consumers by providing a @Bean with the
    // same return type.
    @Bean
    @ConditionalOnMissingBean
    public PrincipalConverter<?> principalConverter() {
        return new IdentityPrincipalConverter();
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------
}
