/*
 * Copyright (C) 2015 Glyptodon LLC
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

import com.google.inject.Inject;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;

/**
 * Service for retrieving configuration information regarding the LDAP server.
 *
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class ConfigurationService {

    /**
     * The Guacamole server environment.
     */
    @Inject
    private Environment environment;

    /**
     * Returns the encryption method that should be used when connecting to the
     * LDAP server. By default, no encryption is used.
     * 
     * Currently the following options are available (the default is socket):
     * <ul>
     *   <li>NONE (default)</li>
     *   <li>SSL</li>
     *   <li>TLS</li>
     * </ul>
     *
     * @return
     *     The encryption method that should be used when connecting to the
     *     LDAP server. The default is {@code NONE}.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public EncryptionMethod getEncryptionMethod() throws GuacamoleException {
        return environment.getProperty(
        	LDAP389dsGuacamoleProperties.LDAP_ENCRYPTION_METHOD,
            EncryptionMethod.NONE
        );
    }

    /**
     * Returns the hostname of the LDAP server as configured with
     * guacamole.properties. By default, this will be "localhost".
     *
     * @return
     *     The hostname of the LDAP server, as configured with
     *     guacamole.properties.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getServerHostname() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_HOSTNAME,
            "localhost"
        );
    }

    /**
     * Returns the port of the LDAP server configured with
     * guacamole.properties. The default value depends on which encryption
     * method is being used. For unencrypted LDAP and STARTTLS, this will be
     * 389. For LDAPS (LDAP over SSL) this will be 636.
     *
     * @return
     *     The port of the LDAP server, as configured with
     *     guacamole.properties.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public int getServerPort() throws GuacamoleException {
        return environment.getProperty(
        	LDAP389dsGuacamoleProperties.LDAP_PORT,
            getEncryptionMethod().DEFAULT_PORT
        );
    }

    /**
     * Returns the technical user (default bind DN) which will be used
     * to bind to the LDAP directory and to perform LDAP operations.
     *
     * @return
     *     The bind DN to use for binding to the LDAP directory.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getDefaultBindDN() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_DEFAULT_BIND_DN
        );
    }

    /**
     * Returns the password of the technical user (default bind DN).
     *
     * @return
     *     The password of bind DN to use for binding to the LDAP directory.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getDefaultAuthtok() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_DEFAULT_AUTHTOK
        );
    }

    /**
     * Returns the LDAP URL for searching the user given in the credentials.
     *
     * @return
     *     The LDAP URL.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getLdapUrlUserByCredentials() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_URL_USER_BY_CREDENTIALS
        );
    }

    /**
     * Returns the LDAP URL for searching the user's guacConfigGroups in the memberOf-Attribute.
     *
     * @return
     *     The LDAP URL.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getLdapUrlUsersGroups() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_URL_USERS_GROUPS
        );
    }

    /**
     * Returns the LDAP URL for searching a guacConfigGroup (given by ${group}).
     *
     * @return
     *     The LDAP URL.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getLdapUrlSearchGuacConfigGroup() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_URL_GUAC_CONFIG_GROUP
        );
    }

    /**
     * Returns the base DN under which all Guacamole configurations
     * (connections) will be stored within the LDAP directory.
     *
     * @return
     *     The base DN under which all Guacamole configurations will be stored
     *     within the LDAP directory.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed, or if the configuration
     *     base DN property is not specified.
     */
    public String getGuacConfigGroupsBaseDN() throws GuacamoleException {
        return environment.getRequiredProperty(
            LDAP389dsGuacamoleProperties.LDAP_GUAC_CONFIG_GROUPS_BASE_DN
        );
    }

}
