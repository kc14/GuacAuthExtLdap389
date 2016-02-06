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

package io.github.kc14.guacamole.auth.ldap389ds;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import io.github.kc14.guacamole.auth.ldap389ds.ldap.LDAPConnectionService;
import io.github.kc14.guacamole.auth.ldap389ds.ldap.searches.LDAPSearchUser;
import io.github.kc14.guacamole.auth.ldap389ds.user.AuthenticatedUser;
import io.github.kc14.guacamole.auth.ldap389ds.user.UserContext;

/**
 * Delegatee service providing convenience functions for the LDAP AuthenticationProvider
 * implementation.
 *
 * @author Michael Jumper
 * @author Frank KemmerØ
 */
public class AuthenticationProviderService {

	/**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(AuthenticationProviderService.class);

    /**
     * Service for creating and managing connections to LDAP servers.
     */
    @Inject
    private LDAPConnectionService ldapService;

    /**
     * Provider for AuthenticatedUser objects.
     */
    @Inject
    private Provider<AuthenticatedUser> authenticatedUserProvider;

    /**
     * Provider for UserContext objects.
     */
    @Inject
    private Provider<UserContext> userContextProvider;
    
    /**
     * Provider for LDAP searches of users.
     */
    @Inject
    private LDAPSearchUser ldapSearchUser;

    public AuthenticatedUser authenticateUser(Credentials credentials)
            throws GuacamoleException {

        // Bind default bindDN
        LDAPConnection ldapConnection = bindDefaultDN();
        if (ldapConnection == null) {
            logger.error("No ldap connection => cannot authenticate!");
            return null;
        }

        // Find user given by credentials
        try {
	    	LDAPSearchResults ldapSearchResults = ldapSearchUser.searchUserByCredentials(ldapConnection, credentials);

            if (ldapSearchResults.hasMore() == false) return null; // No results => not authenticated
            
            // Return AuthenticatedUser if search succeeded
            AuthenticatedUser authenticatedUser = authenticatedUserProvider.get();
            authenticatedUser.init(credentials);
            return authenticatedUser;
        }
        catch (LDAPException e) {
            throw new GuacamoleServerException("Error while searching for user `" + credentials.getUsername() + "'.", e);
        }
        finally { // Always disconnect
        	ldapService.disconnect(ldapConnection);
        }

    }

	/**
     * Returns a UserContext object initialized with data accessible to the
     * given AuthenticatedUser.
     *
     * @param authenticatedUser
     *     The AuthenticatedUser to retrieve data for.
     *
     * @return
     *     A UserContext object initialized with data accessible to the given
     *     AuthenticatedUser.
     *
     * @throws GuacamoleException
     *     If the UserContext cannot be created due to an error.
     */
    public UserContext getUserContext(org.glyptodon.guacamole.net.auth.AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        LDAPConnection ldapConnection = bindDefaultDN(); // Connect to LDAP with technical user
        if (ldapConnection == null) return null;

        try {
            // Build user context by querying LDAP
            UserContext userContext = userContextProvider.get();
            userContext.init(authenticatedUser, ldapConnection);
            return userContext;
        }

        finally { // Always try to disconnect
        	ldapService.disconnect(ldapConnection);
        }

    }

    // Convenience Delegator
    private LDAPConnection bindDefaultDN() throws GuacamoleException {
		return ldapService.bindDefaultDN();
	}

}
