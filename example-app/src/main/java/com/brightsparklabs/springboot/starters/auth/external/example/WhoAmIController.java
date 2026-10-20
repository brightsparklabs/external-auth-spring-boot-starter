/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external.example;

import com.brightsparklabs.springboot.starters.auth.external.example.ExampleConfiguration.MyUser;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoints for checking what the starter resolved the caller to.
 *
 * @author brightSPARK Labs
 */
@RestController
@RequestMapping("/api")
public class WhoAmIController {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** Authority required to call the admin endpoint. */
    public static final String ADMIN_AUTHORITY = "admin";

    // -------------------------------------------------------------------------
    // CLASS VARIABLES
    // -------------------------------------------------------------------------

    /** Class logger. */
    private static final Logger logger = LoggerFactory.getLogger(WhoAmIController.class);

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /**
     * Returns the authenticated user.
     *
     * <p>Logs a line so the MDC username populated by the starter can be checked in the output.
     *
     * @param user The authenticated user, as resolved by the starter.
     * @param authentication The authentication for the current request.
     * @return The authenticated user.
     */
    @GetMapping("/me")
    public WhoAmIResponse me(
            @AuthenticationPrincipal final MyUser user, final Authentication authentication) {
        logger.info("Returning details for the authenticated user.");
        return WhoAmIResponse.of(user, authentication);
    }

    /**
     * Returns a confirmation message, only to callers holding the {@value #ADMIN_AUTHORITY}
     * authority.
     *
     * @param user The authenticated user, as resolved by the starter.
     * @return A confirmation message.
     */
    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('" + ADMIN_AUTHORITY + "')")
    public Map<String, String> admin(@AuthenticationPrincipal final MyUser user) {
        logger.info("Admin endpoint accessed.");
        return Map.of("message", "Hello " + user.username() + ", you have admin access.");
    }
}
