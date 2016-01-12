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

package org.kc.guacamole.auth.ldap389ds;

import com.google.inject.Inject;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.environment.Environment;

/**
 * Service for retrieving configuration information regarding the LDAP server.
 *
 * @author Michael Jumper
 */
public class ConfigurationService {

    /**
     * The Guacamole server environment.
     */
    @Inject
    private Environment environment;

    /**
     * The type of transport to use for connecting to the LDAP server.
     * Currently the following options are available (the default is socket):
     * <ul>
     *   <li>socket (default)</li>
     *   <li>SSL</li>
     *   <li>TLS</li>
     * </ul>
     * 
     * @return
     *     Returns the type of transport. The default is {@code socket}.
     *     
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getLdapTransportLayer() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_TRANSPORT_LAYER,
            "socket"
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
     * guacamole.properties. By default, this will be 389 - the standard LDAP
     * port.
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
            389
        );
    }

    /**
     * Returns the username attribute which should be used to query and bind
     * users using the LDAP directory. By default, this will be "uid" - a
     * common attribute used for this purpose.
     *
     * @return
     *     The username attribute which should be used to query and bind users
     *     using the LDAP directory.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getUsernameAttribute() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_USERNAME_ATTRIBUTE,
            "uid"
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
     * Returns the base DN under which all Guacamole users will be stored
     * within the LDAP directory.
     *
     * @return
     *     The base DN under which all Guacamole users will be stored within
     *     the LDAP directory.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed, or if the user base DN
     *     property is not specified.
     */
    public String getUserBaseDN() throws GuacamoleException {
        return environment.getRequiredProperty(
            LDAP389dsGuacamoleProperties.LDAP_USER_BASE_DN
        );
    }

    /**
     * Returns the the LDAP objectclass of a user entry, usually posixAccount,
     * within the LDAP directory.
     *
     * @return
     *     The LDAP objectclass of user entries in 
     *     the LDAP directory.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getUserObjectClass() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_USER_OBJECTCLASS,
            "posixAccount"
        );
    }

    /**
     * Returns the name of the memberOf attribute for an LDAP user entry.
     * By default, this will be "memberOf".
     *
     * @return
     *     The name of the memberOf attribute, as configured with
     *     guacamole.properties.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getUserMemberOfAttribute() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_USER_MEMBEROF_ATTRIBUTE,
            "memberOf"
        );
    }

    /**
     * Returns the name of the cn-Attribue for an guac configuration group.
     * By default, this will be "cn".
     *
     * @return
     *     The cn-Attribute-Name of a guac configuration group, as configured with
     *     guacamole.properties.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getGuacConfigGroupCnAttribute() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_GUAC_CONFIG_GROUP_CN_ATTRIBUTE,
            "cn"
        );
    }

    /**
     * Returns the prefix for an guac configuration group.
     * By default, this will be "guac".
     *
     * @return
     *     The prefix of a guac configuration group, as configured with
     *     guacamole.properties.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getGuacConfigGroupPrefix() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_GUAC_CONFIG_GROUP_PREFIX,
            "guac"
        );
    }

    /**
     * Returns the objectclass for guac configuration groups.
     * By default, this will be "guacConfigGroup".
     *
     * @return
     *     The prefix of a guac configuration group, as configured with
     *     guacamole.properties.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    public String getGuacConfigGroupObjectClass() throws GuacamoleException {
        return environment.getProperty(
            LDAP389dsGuacamoleProperties.LDAP_GUAC_CONFIG_GROUP_OBJECTCLASS,
            "guacConfigGroup"
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
    public String getConfigurationBaseDN() throws GuacamoleException {
        return environment.getRequiredProperty(
            LDAP389dsGuacamoleProperties.LDAP_CONFIG_BASE_DN
        );
    }

}
