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

package io.github.kc14.guacamole.auth.ldap389ds.user;

import java.util.HashMap;
import java.util.Map;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.novell.ldap.LDAPConnection;

import io.github.kc14.guacamole.auth.ldap389ds.config.ConfigurationService;
import io.github.kc14.guacamole.auth.ldap389ds.ldap.EscapingService;

/**
 * Service for queries the users visible to a particular Guacamole user
 * according to an LDAP directory.
 *
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class UserService {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(UserService.class);

    /**
     * Service for escaping parts of LDAP queries.
     */
    @Inject
    private EscapingService escapingService;

    /**
     * Service for retrieving LDAP server configuration information.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * No subordinate users under authenticated user (sssd like authentication against LDAP)
     *
     * @param ldapConnection
     *     The default bindDN connection to the LDAP server.
     *
     * @return
     *     Empty map of subordinate users
     *
     * @throws GuacamoleException
     *     If an error occurs preventing retrieval of users.
     */
    public Map<String, User> getUsers(LDAPConnection ldapConnection)
            throws GuacamoleException {

    	return new HashMap<String, User>(); // No subordinate users

    }

}
