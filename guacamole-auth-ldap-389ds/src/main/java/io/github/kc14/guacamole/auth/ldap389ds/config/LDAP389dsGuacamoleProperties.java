/*
 * Copyright (C) 2013 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package io.github.kc14.guacamole.auth.ldap389ds.config;

import org.glyptodon.guacamole.properties.BooleanGuacamoleProperty;
import org.glyptodon.guacamole.properties.IntegerGuacamoleProperty;
import org.glyptodon.guacamole.properties.StringGuacamoleProperty;


/**
 * Provides properties required for use of the LDAP authentication provider.
 * These properties will be read from guacamole.properties when the LDAP
 * authentication provider is used.
 *
 * @author Michael Jumper
 */
public class LDAP389dsGuacamoleProperties {

    /**
     * This class should not be instantiated.
     */
    private LDAP389dsGuacamoleProperties() {}

    /**
     * The encryption method to use when connecting to the LDAP server, if any.
     * The chosen method will also dictate the default port if not already
     * explicitly specified via LDAP_PORT.
     */
    public static final EncryptionMethodProperty LDAP_ENCRYPTION_METHOD = new EncryptionMethodProperty() {

        @Override
        public String getName() { return "ldap-encryption-method"; }

    };
    
    /**
     * The hostname of the LDAP server to connect to when authenticating users.
     */
    public static final StringGuacamoleProperty LDAP_HOSTNAME = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-hostname"; }

    };

    /**
     * The port on the LDAP server to connect to when authenticating users.
     */
    public static final IntegerGuacamoleProperty LDAP_PORT = new IntegerGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-port"; }

    };

    /**
     * The default bind DN to use for LDAP operations.
     */
    public static final StringGuacamoleProperty LDAP_DEFAULT_BIND_DN = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-default-bind-dn"; }

    };

    /**
     * The password of the default bind DN to use for LDAP operations.
     */
    public static final StringGuacamoleProperty LDAP_DEFAULT_AUTHTOK = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-default-authtok"; }

    };

    /**
     * The LDAP search to use for finding and authenticating a user (use ${GUAC_USERNAME} to reference the user name and ${GUAC_PASSWORD} for the password).
     */
    public static final StringGuacamoleProperty LDAP_URL_USER_BY_CREDENTIALS = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-url-user-by-credentials"; }

    };
    
    /**
     * Find the groups for an authenticated user (use ${GUAC_USERNAME} to reference the authenticated user name).
     */
    public static final StringGuacamoleProperty LDAP_URL_USERS_GROUPS = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-url-users-groups"; }

    };
    
    /**
     * LDAP URL to find a given guacConfigGroup (use ${GUAC_CONFIG_GROUP} to reference the group to find).
     */
    public static final StringGuacamoleProperty LDAP_URL_GUAC_CONFIG_GROUP = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-url-guac-config-group"; }

    };

    /**
     * The base DN to search for Guacamole configurations.
     */
    public static final StringGuacamoleProperty LDAP_GUAC_CONFIG_GROUPS_BASE_DN = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-guac-config-groups-base-dn"; }

    };

}
