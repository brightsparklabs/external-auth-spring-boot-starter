/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.ValidExternalAuthConfiguration;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Binds the {@code bsl.auth} configuration tree used by the externally authenticated auth starter.
 *
 * <p>The active authentication method is selected via {@link #method()}.
 *
 * @param method The authentication method to use.
 * @param mdcUsernameField Key in the MDC that the authenticated user's username is stored against,
 *     used for access logging. Shared by all methods.
 * @param user The user to use for the {@link AuthMethod#DEV} method. Ignored otherwise.
 * @author brightSPARK Labs
 */
@Validated
@ValidExternalAuthConfiguration
@ConfigurationProperties(prefix = "brightsparklabs.auth")
public record ExternallyAuthenticatedAuthStarterConfiguration(
        @NotNull AuthMethod method,
        @NotBlank String mdcUsernameField,
        Optional<InternalUser> user) {

    // -------------------------------------------------------------------------
    // INNER CLASSES
    // -------------------------------------------------------------------------

    /**
     * Validates that the overall configuration is internally consistent.
     *
     * <p>Specifically, a dummy user must be supplied when the {@link AuthMethod#DEV} method is in
     * use.
     */
    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    @Constraint(validatedBy = ExternalAuthConfigurationValidator.class)
    public @interface ValidExternalAuthConfiguration {
        /**
         * Returns the message shown when validation fails.
         *
         * @return The validation failure message.
         */
        String message() default "A dummy user must be defined when using the developer method.";

        /**
         * Returns the validation groups this constraint belongs to.
         *
         * @return The validation groups.
         */
        Class<?>[] groups() default {};

        /**
         * Returns the payload associated with this constraint.
         *
         * @return The constraint payload.
         */
        Class<? extends Payload>[] payload() default {};
    }

    /** Enforces the {@link ValidExternalAuthConfiguration} cross-field constraint. */
    public static class ExternalAuthConfigurationValidator
            implements ConstraintValidator<
                    ValidExternalAuthConfiguration,
                    ExternallyAuthenticatedAuthStarterConfiguration> {

        @Override
        public boolean isValid(
                final ExternallyAuthenticatedAuthStarterConfiguration value,
                final ConstraintValidatorContext context) {
            // If the value is null, let @NotBlank or @NotNull handle it.
            if (value == null) {
                return true;
            }

            // If the method is DEV then a user must be provided.
            return value.method() != AuthMethod.DEV || value.user().isPresent();
        }
    }

    /** The supported authentication methods. */
    public enum AuthMethod {
        /** User principal properties are provided via OAuth2 headers. */
        HTTP_HEADERS,

        /**
         * A fixed user principal is provided for all requests.
         *
         * <p>DO NOT USE THIS IN PRODUCTION.
         */
        DEV,
    }
}
