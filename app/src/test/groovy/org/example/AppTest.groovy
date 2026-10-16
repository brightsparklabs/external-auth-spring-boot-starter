/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package org.example

import spock.lang.Specification

class AppTest extends Specification {
    def "application has a greeting"() {
        setup:
        def app = new App()

        when:
        def result = app.greeting

        then:
        result != null
    }
}
