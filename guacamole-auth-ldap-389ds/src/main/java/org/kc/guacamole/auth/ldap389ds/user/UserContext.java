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

package org.kc.guacamole.auth.ldap389ds.user;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.form.Form;
import org.glyptodon.guacamole.net.auth.ActiveConnection;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.AuthenticationProvider;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.ConnectionGroup;
import org.glyptodon.guacamole.net.auth.Directory;
import org.glyptodon.guacamole.net.auth.User;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroup;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroupDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleUser;
import org.glyptodon.guacamole.token.StandardTokens;
import org.glyptodon.guacamole.token.TokenFilter;
import org.kc.guacamole.auth.ldap389ds.connection.ConnectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.novell.ldap.LDAPConnection;

import net.sourceforge.guacamole.net.auth.ldap389ds.LDAP389dsAuthenticationProvider;

/**
 * An LDAP-specific implementation of UserContext which queries all Guacamole
 * connections and users from the LDAP directory.
 *
 * @author Michael Jumper
 */
public class UserContext implements org.glyptodon.guacamole.net.auth.UserContext {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(UserContext.class);

    /**
     * Service for retrieving Guacamole connections from the LDAP server.
     */
    @Inject
    private ConnectionService connectionService;

    /**
     * Service for retrieving Guacamole users from the LDAP server.
     */
    @Inject
    private UserService userService;

    /**
     * Reference to the AuthenticationProvider associated with this
     * UserContext.
     */
    @Inject
    private AuthenticationProvider authProvider;

    /**
     * Reference to a User object representing the user whose access level
     * dictates the users and connections visible through this UserContext.
     */
    private User self;

    /**
     * Directory containing all User objects accessible to the user associated
     * with this UserContext.
     */
    private Directory<User> userDirectory;

    /**
     * Directory containing all Connection objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<Connection> connectionDirectory;

    /**
     * Directory containing all ConnectionGroup objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<ConnectionGroup> connectionGroupDirectory;

    /**
     * Reference to the root connection group.
     */
    private ConnectionGroup rootGroup;

    /**
     * Initializes this UserContext using the provided AuthenticatedUser and
     * LDAPConnection.
     *
     * @param user
     *     The AuthenticatedUser representing the user that authenticated. This
     *     user may have been authenticated by a different authentication
     *     provider (not LDAP).
     *
     * @param ldapConnection
     *     The connection to the LDAP server to use when querying accessible
     *     Guacamole users and connections.
     *
     * @throws GuacamoleException
     *     If associated data stored within the LDAP directory cannot be
     *     queried due to an error.
     */
    public void init(AuthenticatedUser user, LDAPConnection ldapConnection)
            throws GuacamoleException {

        // Query all accessible users
        userDirectory = new SimpleDirectory<User>(
            userService.getUsers(ldapConnection)
        );

        // Query all accessible connections
        Map<String, Connection> connections = connectionService.getConnections(user, ldapConnection);
        
        // Build credential TokenFilter
        TokenFilter tokenFilter = new TokenFilter();
        StandardTokens.addStandardTokens(tokenFilter, user.getCredentials());

        // Filter each configuration
        for (Connection connection : connections.values()) {
        	tokenFilter.filterValues(connection.getConfiguration().getParameters());
        }
        
        // Create a simple read-only directory from the filtered connections
        connectionDirectory = new SimpleDirectory<Connection>(
        	connections
        );

        // Root group contains only connections
        rootGroup = new SimpleConnectionGroup(
            LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP,
            LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP,
            connectionDirectory.getIdentifiers(),
            Collections.<String>emptyList()
        );

        // Expose only the root group in the connection group directory
        connectionGroupDirectory = new SimpleConnectionGroupDirectory(Collections.singleton(rootGroup));

        // Init self with basic permissions
        self = new SimpleUser(
            user.getIdentifier(),
            userDirectory.getIdentifiers(),
            connectionDirectory.getIdentifiers(),
            connectionGroupDirectory.getIdentifiers()
        );

    }

    @Override
    public User self() {
        return self;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Directory<User> getUserDirectory() throws GuacamoleException {
        return userDirectory;
    }

    @Override
    public Directory<Connection> getConnectionDirectory()
            throws GuacamoleException {
        return connectionDirectory;
    }

    @Override
    public Directory<ConnectionGroup> getConnectionGroupDirectory()
            throws GuacamoleException {
        return connectionGroupDirectory;
    }

    @Override
    public ConnectionGroup getRootConnectionGroup() throws GuacamoleException {
        return rootGroup;
    }

    @Override
    public Directory<ActiveConnection> getActiveConnectionDirectory()
            throws GuacamoleException {
        return new SimpleDirectory<ActiveConnection>();
    }

    @Override
    public Collection<Form> getUserAttributes() {
        return Collections.<Form>emptyList();
    }

    @Override
    public Collection<Form> getConnectionAttributes() {
        return Collections.<Form>emptyList();
    }

    @Override
    public Collection<Form> getConnectionGroupAttributes() {
        return Collections.<Form>emptyList();
    }

}
