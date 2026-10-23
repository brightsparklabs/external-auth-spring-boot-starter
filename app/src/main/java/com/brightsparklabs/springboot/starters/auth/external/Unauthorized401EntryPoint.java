/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * {@link AuthenticationEntryPoint} implementation that maps exceptions to a 401 Unauthorized
 * response.
 *
 * @author brightSPARK Labs
 */
public class Unauthorized401EntryPoint implements AuthenticationEntryPoint {
    /** Class logger. */
    private static final Logger logger = LoggerFactory.getLogger(Unauthorized401EntryPoint.class);

    @Override
    public void commence(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final AuthenticationException authException)
            throws IOException {

        logger.debug(
                "Rejecting unauthenticated request to [{}]: {}",
                request.getRequestURI(),
                authException.getMessage());

        // Set the status directly rather than calling sendError(), which would
        // forward to the /error page and run the security chain a second time.
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.TEXT_PLAIN_VALUE);
        response.getWriter().write("Credentials are required to access this resource.");
    }
}
