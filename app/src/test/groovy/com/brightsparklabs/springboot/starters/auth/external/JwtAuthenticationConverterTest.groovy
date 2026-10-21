/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external

import static com.brightsparklabs.springboot.starters.auth.external.ExternalAuthAutoConfiguration.*

import com.google.common.collect.ImmutableSet
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import spock.lang.Specification

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * Unit tests for the JWT claims mapping performed by {@link
 * ExternalAuthAutoConfiguration#jwtAuthenticationConverter}.
 *
 * <p>Each token is decoded and signature-checked with Spring Security's {@link NimbusJwtDecoder},
 * as the resource server does, then mapped by the converter under test. Token expiry is not
 * validated, so the hard-coded Keycloak tokens do not cause the tests to fail once they expire.
 *
 * @author brightSPARK Labs
 */
class JwtAuthenticationConverterTest extends Specification {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** Issuer included in generated tokens. */
    static final String ISSUER = "https://idp.example.com/realms/test"

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Converter under test, using {@link InternalUser} as the principal. */
    final Converter<Jwt, ? extends AbstractAuthenticationToken> converter =
    new ExternalAuthAutoConfiguration().jwtAuthenticationConverter(new IdentityPrincipalConverter())

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "convert Keycloak token maps user details"() {
        given:
        final String key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmKF1iO+fjks9Oi69UezToxw/jNvYmvxKnBt6eBX12j+RYkvnF1dnufZ7y4JNloaIgb8m/piV5TAu/rF3ICsniKRKO2xOfiS/EJfguALnDyA2Ko6tHYjsdmzbL3+tKd/oXjFXbL59I2hYbxo3+gi16cCzvdI6jD91OJJ9BEFGSKvkmxXsvYNzMsEHfsiflyLTiUYHLOLVRXfT3AYP67nF2gVSkUmkNV1Gn7EyORTw2VoAJF3uI+J6cGivCGoi7ClisCLxUYgFfA8jvRzjLkkbeIvqlW3lnh+qGRwNw73fum8UqVs/Y6rOYfDfAHCO1IieroqnuUn2j6f1eyhjkZlXjwIDAQAB"

        // Hard coded, manually made using Keycloak.
        final String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJGNWVxSUlSR1gwT2hIUmMtYl9TT0hGb2ZQbWVxNlcydUJaVVgxYWQxd0NjIn0.eyJqdGkiOiIyZmNkYmZmYy0wMzZhLTQzNWItODMzNy1hMGE2Njk3ZWE3ZGQiLCJleHAiOjE5MTgxODI3NzUsIm5iZiI6MCwiaWF0IjoxNTcyNTg2OTE0LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwOTAvYXV0aC9yZWFsbXMvb3Ntb3NpcyIsImF1ZCI6WyJvc21vc2lzIiwiYWNjb3VudCJdLCJzdWIiOiIwMjk5ODEzYy1kY2YyLTQ1YWYtYjE4Ny02YmU4NTVlYjVmZjYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJvc21vc2lzIiwiYXV0aF90aW1lIjoxNTcyNTg2NzExLCJzZXNzaW9uX3N0YXRlIjoiMjUyM2ExMzQtYmQ4NC00ZjEwLWE5MzMtNjNmYzY2YWU3Y2FjIiwiYWNyIjoiMCIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjgwODAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJBRE1JTiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7Im9zbW9zaXMiOnsicm9sZXMiOlsiQ2xpZW50Um9sZSJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiYWRtaW4gYWRtaW4iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiIsImdpdmVuX25hbWUiOiJhZG1pbiIsImZhbWlseV9uYW1lIjoiYWRtaW4iLCJlbWFpbCI6ImFkbWluQGVtYWlsLmNvbSJ9.bjUt_5QMyKvcsTRwPQwBkW22n_6-0HZV3ecMumEYVl4vUM8fDm3nNymjbsELPo0A2oH5bPejtIBCw7Wma_f2PKsFOeS0pOfy2YzNkbmwQRPFVkCRMLwsaz9buNxwSYU7KU2NCzRRLoOlOtD4J0kYQquktuuunMFprTwwxCkAiWONlFDg2dkXM9B6SWVhlF511dZbVMppD0_Rk2e6jAx2Uef1CzSddAlZkV7VM_3Q7hHAy0FTDoBHh70MYY9jtaTxCXU8ws3W81BUp0RCvcBSW-_IB6u3M6GvreHGtMGcXtsx1ZjpcZcFPN0Diccsuvv328eP-R3K6zDorTaRzmEuYg"

        when:
        final InternalUser user = convert(token, key)

        then:
        user == new InternalUser(
                "admin",
                "admin",
                "admin",
                Optional.of("admin@email.com"),
                [] as Set,
                [
                    // Realm roles.
                    "offline_access",
                    "uma_authorization",
                    "ADMIN",
                    // Client roles - osmosis.
                    "ClientRole",
                    // Client roles - account.
                    "manage-account",
                    "manage-account-links",
                    "view-profile"
                ] as Set,
                Optional.of("http://localhost:8090/auth/realms/osmosis/protocol/openid-connect/logout"))
    }

    def "convert Keycloak token without email maps empty email"() {
        given:
        final String key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty2VYUBIBOhYV6fgTt/yvTQZ9SUX7L+TIUZqcknAJ4LO/LTG5QbGgKiKRwb5F8vDDTRhqAOB2QrweTDCLRk3920zTCrvCYILTN9RWx9a+w1zFRTCkeDN3d6ekFg+FxkKsMROtDEIXktdNdbhwYwHnY8n1drxW9fNRsPFfMsO0/zI65g5f0I0UsX1JDWKIoNOZpWxSMCL9OcRFo3luPonw9gIr0c5G47O7PX+CUcx3G+VTvoftrNbGXa1s3J76/g/S0EbnwtpXSpUqn5nGKp6QvdGDlbkmfJDi+vgD6FK+WaNttlac+o1sxaxi20ZmEXnd3iJ6okvqjURtCchKsocPQIDAQAB"

        // Hard coded, manually made using Keycloak.
        final String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJVeEh2ZUtxRDk4ay1aRlhMY2poNWsyQzdJZEZ4cFZ6NUU0cXpHbFR3NV9VIn0.eyJqdGkiOiIxY2VlYjViZS03MDlmLTQ5NzUtYjcwOC1jY2QwYWUyZDk0ZmUiLCJleHAiOjE4NjU2NDMxNzYsIm5iZiI6MCwiaWF0IjoxNTc3NjcyMTc5LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwOTAvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjJkNzNkNDE4LWMzNzItNDM5NS1hOTMzLTRmOTc5OWZhOTQ2ZCIsInR5cCI6IkJlYXJlciIsImF6cCI6Im9zbW9zaXMiLCJhdXRoX3RpbWUiOjE1Nzc2NzE5NzYsInNlc3Npb25fc3RhdGUiOiJiMGNhZGQzZi1jMWZlLTQwMmItOTI5Zi1kOTJkODA2ZjRiZGEiLCJhY3IiOiIwIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIlRFU1QiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoibm8gZW1haWwiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJub2VtYWlsIiwiZ2l2ZW5fbmFtZSI6Im5vIiwiZmFtaWx5X25hbWUiOiJlbWFpbCJ9.Uu8mS2VOzHyvUG7qSYMmIvUmEEhLNb-1wBwOg2CrCRHOojf2PXp6kYs436uxJgJUET4lWnB8RVJR6VzGY7-6grdS-60AUX7-a5U4xzJ1_uh_MnFBdhWv_kuyZO6Hh1BfkC54RPo1QdxNLYDYX6hcOYs1KTi8t4psPj0MLyp74TN-vv_DOhaBK_COuYaNzs1m9RCDJFv78uNwCblYa8UKdtotdyxNLd2QIy0px5fAasw_Mmiizjqug0GRVY7RFx6TeRabus44WWMTtBSFWBKFbO8ml7oCgQ4xUuR8IMXseUwRSlG258HBv5vZaXuMygyDxOfUk1cQX-prMH0Sz4vF6Q"


        when:
        final InternalUser user = convert(token, key)

        then:
        user == new InternalUser(
                "noemail",
                "no",
                "email",
                Optional.empty(),
                [] as Set,
                [
                    // Realm roles.
                    "TEST",
                    "offline_access",
                    "uma_authorization",
                    // Client roles.
                    "manage-account",
                    "manage-account-links",
                    "view-profile"
                ] as Set,
                Optional.of("http://localhost:8090/auth/realms/master/protocol/openid-connect/logout"))
    }

    def "convert token without issuer maps empty logout URL"() {
        given:
        final Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .claim(CLAIM_FIELD_USERNAME, "test.user")
                .claim(CLAIM_FIELD_FIRSTNAME, "Test")
                .claim(CLAIM_FIELD_LASTNAME, "User")
                .build()

        when:
        final InternalUser user = converter.convert(jwt).principal as InternalUser

        then:
        user.logoutUrl() == Optional.empty()
    }

    def "convert token #description maps groups and merges roles from all claims"() {
        given:
        final KeyPair keyPair = createKeyPair()
        final String token = createJwt(
                "test.user",
                "Test",
                "User",
                "test.user@test.test",
                groups,
                roles,
                realmRoles,
                clientRoles,
                keyPair.getPrivate())

        when:
        final InternalUser user = convert(token, keyPair.getPublic() as RSAPublicKey)

        then:
        final allClientRoles = clientRoles?.values()?.flatten() ?: []
        user == new InternalUser(
                "test.user",
                "Test",
                "User",
                Optional.of("test.user@test.test"),
                ImmutableSet.copyOf(groups ?: []),
                ImmutableSet.builder()
                .addAll(roles ?: [])
                .addAll(realmRoles ?: [])
                .addAll(allClientRoles)
                .build(),
                Optional.of("${ISSUER}/protocol/openid-connect/logout".toString()))

        // spotless:off
        where:
        description       | groups       | roles                             | realmRoles            | clientRoles
        "with groups"      | ["G1", "G2"] | null                              | null                  | null
        "with roles"       | null         | ["R1", "R2", "GR1", "GR2", "GR3"] | null                  | null
        "with realmRoles"  | null         | null                              | ["RR1", "RR2", "GR1"] | null
        "with clientRoles" | null         | null                              | null                  |
                [
                        client1: ["C1R1", "C1R2", "GR2", "COMMON_CLIENT"],
                        client2: ["C2R1", "C2R2", "GR3", "COMMON_CLIENT"],
                ] as Map<String, List<String>>;

        "with groups+roles+realmRoles+clientRoles" |
                ["G1", "G2"]                |
                ["R1", "R2", "GR1", "GR2", "GR3"] |
                ["RR1", "RR2", "GR1"]               |
                [
                        client1: ["C1R1", "C1R2", "GR2", "COMMON_CLIENT"],
                        client2: ["C2R1", "C2R2", "GR3", "COMMON_CLIENT"],
                ] as Map<String, List<String>>;
        // spotless:on
    }


    // -------------------------------------------------------------------------
    // FIXTURES
    // -------------------------------------------------------------------------

    /**
     * Decodes and signature-checks a token, then converts it to a user.
     *
     * @param token The encoded token.
     * @param publicKey Base64-encoded X.509 RSA public key to verify the signature with.
     * @return The user built by the converter under test.
     */
    private InternalUser convert(final String token, final String publicKey) {
        final keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey))
        return convert(token, KeyFactory.getInstance("RSA").generatePublic(keySpec) as RSAPublicKey)
    }

    /**
     * Decodes and signature-checks a token, then converts it to a user.
     *
     * @param token The encoded token.
     * @param publicKey RSA public key to verify the signature with.
     * @return The user built by the converter under test.
     */
    private InternalUser convert(final String token, final RSAPublicKey publicKey) {
        final decoder = NimbusJwtDecoder.withPublicKey(publicKey).build()
        // Skip expiry checks so the hard-coded tokens remain usable.
        decoder.setJwtValidator({ OAuth2TokenValidatorResult.success() } as OAuth2TokenValidator<Jwt>)
        return converter.convert(decoder.decode(token)).principal as InternalUser
    }

    /**
     * Creates a new RSA key pair.
     *
     * @return A new RSA 2048-bit key pair.
     */
    def createKeyPair() {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        return generator.generateKeyPair()
    }

    /**
     * Returns a new JWT containing the supplied information and signed with the provided private key.
     *
     * @param username Username to include.
     * @param firstname Firstname to include.
     * @param lastname Last to include.
     * @param email Email to include.
     * @param groups Group memberships to include.
     * @param roles Roles to include.
     * @param realmRoles Realm roles (Keycloak) to include.
     * @param clientRoles Client roles (Keycloak) to include.
     * @param privateKey Private key to sign the JWT with.
     * @return The newly created JWT.
     */
    String createJwt(String username,
            String firstname, String lastname, String email, List<String> groups,
            List<String> roles, List<String> realmRoles = [], Map<String,
            List<String>> clientRoles = [:], PrivateKey privateKey) {

        Map<String, Object> claims = [
            iss                     : ISSUER,
            (CLAIM_FIELD_USERNAME)  : username,
            (CLAIM_FIELD_FIRSTNAME) : firstname,
            (CLAIM_FIELD_LASTNAME)  : lastname,
            (CLAIM_FIELD_EMAIL)     : email,
        ]

        if (groups != null) {
            claims[CLAIM_FIELD_GROUPS] = groups
        }

        if (roles != null) {
            claims[CLAIM_FIELD_ROLES] = roles
        }

        if (realmRoles != null) {
            claims[CLAIM_FIELD_REALM_ACCESS] = [roles: realmRoles]
        }

        if (clientRoles != null) {
            /*
             * Transforms:
             *
             *   [
             *      client1: ["ROLE1", "ROLE2"],
             *      client2: ["ROLE3", "ROLE4"],
             *   ]
             *
             * Into:
             *
             *   [
             *      client1:
             *        roles: ["ROLE1", "ROLE2"],
             *      client2:
             *        roles: ["ROLE3", "ROLE4"],
             *   ]
             */
            def reshapeClientRoles =
                    clientRoles
                    .collectEntries { entry -> [(entry.key): [roles: entry.value]] }
            claims[CLAIM_FIELD_RESOURCE_ACCESS] = reshapeClientRoles
        }

        final SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), JWTClaimsSet.parse(claims))
        jwt.sign(new RSASSASigner(privateKey))
        return jwt.serialize()
    }
}