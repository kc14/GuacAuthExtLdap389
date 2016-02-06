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

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Vector;

import static io.github.kc14.com.novell.ldap.util.DNHelper.*;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

import io.github.kc14.guacamole.auth.ldap389ds.connection.ConnectionService;
import io.github.kc14.guacamole.auth.ldap389ds.connection.ConnectionTreeContext;
import io.github.kc14.guacamole.auth.ldap389ds.utils.MacroPreProcessor;
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
    
    @Inject
    private ConnectionTreeContext folderTreeContext;

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
    public void init(AuthenticatedUser user, LDAPConnection ldapConnection) throws GuacamoleException {

        // Query all accessible users
        userDirectory = new SimpleDirectory<User>(
            userService.getUsers(ldapConnection)
        );

        // Query all accessible connections
        Map<String, Connection> connections = connectionService.getConnections(user, ldapConnection);
        
        MacroPreProcessor.expandStandardTokens(user, connections);
        
        folderTreeContext.putConnections (connections);
        
        // Init self with basic permissions
        createSimpleUser(user);

    }

	private void createSimpleUser(AuthenticatedUser user) throws GuacamoleException {
		self = new SimpleUser(
            user.getIdentifier(),
            userDirectory.getIdentifiers(),
            getConnectionDirectory().getIdentifiers(),
            getConnectionGroupDirectory().getIdentifiers()
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
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
        return folderTreeContext.getConnectionMap();
    }

    @Override
    public Directory<ConnectionGroup> getConnectionGroupDirectory() throws GuacamoleException {
        return folderTreeContext.getFolderMap();
    }

    @Override
    public ConnectionGroup getRootConnectionGroup() throws GuacamoleException {
    	return folderTreeContext.getRootFolder();
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
