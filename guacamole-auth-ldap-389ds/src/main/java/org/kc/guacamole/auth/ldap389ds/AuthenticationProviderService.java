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

import java.io.UnsupportedEncodingException;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.kc.guacamole.auth.ldap389ds.user.AuthenticatedUser;
import org.kc.guacamole.auth.ldap389ds.user.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.google.inject.Provider;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPJSSEStartTLSFactory;
import com.novell.ldap.LDAPSearchResults;

/**
 * Delegatee service providing convenience functions for the LDAP AuthenticationProvider
 * implementation.
 *
 * @author Michael Jumper
 * @author Frank KemmerØ
 */
public class AuthenticationProviderService {

    private static final String LDAP_TRANSPORT_LAYER_SOCKET = "socket";
    private static final String LDAP_TRANSPORT_LAYER_SSL = "SSL";
    private static final String LDAP_TRANSPORT_LAYER_TLS = "TLS";

	/**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(AuthenticationProviderService.class);

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
     * Binds to the LDAP server using the default bindDN provided by the
     * Guacamole configuration.
     *  
     * The bindDN comes from the LDAP configuration properties provided 
     * in guacamole.properties, as is the server hostname and port
     * information.
     *
     * @return
     *     A bound LDAP connection, or null if the connection could not be
     *     bound.
     *
     * @throws GuacamoleException
     *     If an error occurs while binding to the LDAP server.
     */
    private LDAPConnection bindDefaultDN()
            throws GuacamoleException {

            LDAPConnection ldapConnection = null;
            
            // We allow empty, i.e. anonymous, bindDN ... but in most cases this will fail
            String bindDN = confService.getDefaultBindDN();
            String authtok = confService.getDefaultAuthtok();
            String transportLayer = confService.getLdapTransportLayer();

            // Log empty bindDN
            if (bindDN == null) {
                logger.warn("Anonymous bindDN in LDAP authentication provider.");
                bindDN = "";
            }

            // No password? Warn about it ...
            if (authtok == null || authtok.length() == 0) {
                logger.warn("Anonymous bindDN with empty authtok.");
                authtok = "";
            }

            // Check which transport layer to use for connection to the LDAP server
			try {
				if (transportLayer.equalsIgnoreCase(LDAP_TRANSPORT_LAYER_SOCKET)) {	
					ldapConnection = new LDAPConnection();
				}
				else if (transportLayer.equalsIgnoreCase(LDAP_TRANSPORT_LAYER_SSL) || transportLayer.equalsIgnoreCase(LDAP_TRANSPORT_LAYER_TLS)) {
					ldapConnection = new LDAPConnection(new LDAPJSSESecureSocketFactory()); // TLS 1.0 is SSL 3.1 https://de.wikipedia.org/wiki/Transport_Layer_Security
				}
				else {
					logger.error("Unable to connect to LDAP server: no transport layer configured (use property: `{}')", LDAP389dsGuacamoleProperties.LDAP_TRANSPORT_LAYER.getName());
					return null;
				}
				ldapConnection.connect(confService.getServerHostname(), confService.getServerPort());
			} catch (LDAPException e) {
				logger.error("Unable to connect to LDAP server: {}", e.getMessage());
				logger.debug("Failed to connect to LDAP server.", e);
				return null;
			}

            // Bind using configured default bindDN
            try {

                // Bind the default bindDN
                try {
                    ldapConnection.bind(LDAPConnection.LDAP_V3, bindDN, authtok.getBytes("UTF-8"));
                }
                catch (UnsupportedEncodingException e) {
                    logger.error("Unexpected lack of support for UTF-8: {}", e.getMessage());
                    logger.debug("Support for UTF-8 (as required by Java spec) not found.", e);
                    return null;
                }

                // Disconnect if an error occurs during bind
                catch (LDAPException e) {
                    ldapConnection.disconnect();
                    throw e;
                }

            }
            catch (LDAPException e) {
            	logger.error("LDAP bind for default DN `" + bindDN + "' failed", e);
                return null;
            }

            return ldapConnection;

        }

    public AuthenticatedUser authenticateUser(Credentials credentials)
            throws GuacamoleException {

        // Bind default bindDN
        LDAPConnection ldapConnection = bindDefaultDN();
        if (ldapConnection == null) {
            logger.error("No ldap connection => cannot authenticate!");
            return null;
        }

        // LDAP search for user
        // Find user given by credentials
    	String userBaseDN = confService.getUserBaseDN(); 
        int searchScopeBase = LDAPConnection.SCOPE_BASE;
        String userObjectClass = confService.getUserObjectClass();
        String usernameAttribute = confService.getUsernameAttribute();
        String username = credentials.getUsername();
        String userSearchFilter = "(&(objectClass=" + userObjectClass + ")(" + escapingService.escapeLDAPSearchFilter(usernameAttribute) + "=" + username + "))";
        String attrsAll[] = null;
        boolean typesOnlyFalse = false;            
        try {
            LDAPSearchResults ldapSearchResults = ldapConnection.search(userBaseDN, searchScopeBase, userSearchFilter, attrsAll, typesOnlyFalse);

            if (ldapSearchResults.hasMore() == false) return null; // No results => not authenticated
            
            // Return AuthenticatedUser if search succeeded
            AuthenticatedUser authenticatedUser = authenticatedUserProvider.get();
            authenticatedUser.init(credentials);
            return authenticatedUser;
        }
        catch (LDAPException e) {
            throw new GuacamoleServerException("Error while searching for user `" + username + "'.", e);
        }
        finally { // Always disconnect
            try { // Attempt disconnect
                ldapConnection.disconnect();
            }
            catch (LDAPException e) { // Warn if disconnect unexpectedly fails
                logger.warn("Unable to disconnect from LDAP server: {}", e.getMessage());
                logger.debug("LDAP disconnect failed.", e);
            }
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
            try { // Attempt disconnect
                ldapConnection.disconnect();
            }
            catch (LDAPException e) { // Warn if disconnect unexpectedly fails
                logger.warn("Unable to disconnect from LDAP server: {}", e.getMessage());
                logger.debug("LDAP disconnect failed.", e);
            }
        }

    }

}
