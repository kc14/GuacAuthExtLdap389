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

package io.github.kc14.guacamole.auth.ldap389ds.connection;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnection;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

import io.github.kc14.guacamole.auth.ldap389ds.config.ConfigurationService;
import io.github.kc14.guacamole.auth.ldap389ds.ldap.EscapingService;
import io.github.kc14.guacamole.auth.ldap389ds.ldap.searches.LDAPSearchGuacConfigGroup;
import io.github.kc14.guacamole.auth.ldap389ds.ldap.searches.LDAPSearchUsersGroups;
import net.sourceforge.guacamole.net.auth.ldap389ds.LDAP389dsAuthenticationProvider;

/**
 * Service for querying the connections available to a particular Guacamole
 * user according to an LDAP directory.
 *
 * @author Michael Jumper
 * @author Frank Kemmer
 */
public class ConnectionService {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(ConnectionService.class);

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
     * Provider for LDAP searches of a user's groups.
     */
    @Inject
    private LDAPSearchUsersGroups ldapSearchUsersGroups;

    /**
     * Provider for LDAP searches of guac config groups.
     */
    @Inject
    private LDAPSearchGuacConfigGroup ldapSearchGuacConfigGroup;

    private static final List<String> GUAC_CONFIG_GROUP_ATTRIBUTES = new ArrayList<String>() {{
        add("cn");
        add("guacConfigProtocol");
        add("guacConfigParameter");
    }};

	/**
	 * Search for the authenticated user entry 
	 * @param ldapConnection
	 *     The LDAP connection to use, bind with the default bind DN,
	 *     i.e. the technical user to query the LDAP directory service
	 * @param user
	 *     The authenticated user
	 * 
	 * @return
	 * @throws GuacamoleException
	 */
	protected LDAPSearchResults ldapsearchUsersGroups(LDAPConnection ldapConnection, AuthenticatedUser user) throws GuacamoleException {
        try {
            LDAPSearchResults userEntryMemberOfSearchResult = ldapSearchUsersGroups.searchUsersGroups(ldapConnection, user);
            return userEntryMemberOfSearchResult;      
        }
        catch (LDAPException e) {
        	if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
        		logger.info("No user entry found for [" + user.getCredentials().getUsername() + "] by ldap url [" + confService.getLdapUrlUsersGroups() + "]");
        		return null;
        	}
            throw new GuacamoleServerException("Error while searching for groups of user [" + user.getCredentials().getUsername() + "] by ldap url [" + confService.getLdapUrlUsersGroups() + "].", e);
        }
        catch (MalformedURLException e) {
            throw new GuacamoleServerException("Error[Malformed URL] while searching for groups of user [" + user.getCredentials().getUsername() + "] by ldap url [" + confService.getLdapUrlUsersGroups() + "].", e);
        }
	}
	
	/**
	 * LDAP search for the guac configuration group given as DN in guacConfigGroup
	 * @param ldapConnection
	 *     The LDAP connection to use, bind with the default bind DN,
	 *     i.e. the technical user to query the LDAP directory service
	 * @param guacConfigGroup
	 *     The DN of a guacConfigGroup as given in the memberOf-Attribute
	 *     of the posixAccount of the authenticated user
	 * @return
	 *     The LDAP search result containing the base entry for the given guac config group
	 *     retrieving the attributes given in GUAC_CONFIG_GROUP_ATTRIBUTES
	 * @throws GuacamoleException
	 */
	protected LDAPSearchResults ldapsearchGuacConfigGroup(LDAPConnection ldapConnection, String guacConfigGroup) throws GuacamoleException {
		try {
			LDAPSearchResults guacConfigGroupsSearchResult = ldapSearchGuacConfigGroup.ldapsearchGuacConfigGroup(ldapConnection, guacConfigGroup);
			return guacConfigGroupsSearchResult;
		} catch (LDAPException e) {
			throw new GuacamoleServerException("Error while searching for guac configuration group `" + guacConfigGroup + "'.", e);
		} catch (MalformedURLException e) {
            throw new GuacamoleServerException("Error[Malformed URL] while searching for guac config group [" + guacConfigGroup + "] by ldap url [" + confService.getLdapUrlSearchGuacConfigGroup() + "].", e);
        }
	}

	/**
	 * Parse the config parameters in the LDAP parameter attribute into the configuration 
	 * 
	 * @param parameterAttribute
	 *     The value of the ldap guac config parameter attribute
	 * @param config
	 */
	protected void processGuacConfigGroupParameters(LDAPAttribute parameterAttribute, GuacamoleConfiguration config) {
		// Get parameters, if any
		if (parameterAttribute != null) {

			// For each parameter
			Enumeration<?> parameters = parameterAttribute.getStringValues();
			while (parameters.hasMoreElements()) {

				String parameter = (String) parameters.nextElement();

				// Parse parameter
				int equals = parameter.indexOf('=');
				if (equals != -1) {

					// Parse name
					String name = parameter.substring(0, equals);
					String value = parameter.substring(equals + 1);

					config.setParameter(name, value);
				}
			}
		}
	}
	
	/**
	 * Iterate over all guac config groups in the given ldap search result and
	 * process the following attributes in the entry to create a connection config:
	 * 
	 *    cn: the guac config group name
	 *    guacConfigProtocol: the protocol, eg. VPN, SSH, etc.
	 *    guacConfigParameter: more parameters to use for configuration of the guac connection
	 * @param guacConfigGroupsSearchResult
	 *     The LDAP search result containing the guac config group entries to process
	 * @return
	 *     The connections configured by the given guac config groups 
	 * @throws GuacamoleServerException
	 */
	protected Map<String, Connection> processGuacConfigGroupLdapEntries(LDAPSearchResults guacConfigGroupsSearchResult) throws GuacamoleServerException {
		// Produce connections for each readable configuration
		Map<String, Connection> connections = new HashMap<String, Connection>();
		try {
			while (guacConfigGroupsSearchResult.hasMore()) { // Should be only one group as we query one by one for each group name given in memberOf

				LDAPEntry guacConfigGroupEntry = guacConfigGroupsSearchResult.next();

				// Get common name (CN)
				LDAPAttribute cn = guacConfigGroupEntry.getAttribute("cn");
				if (cn == null) {
					logger.warn("guacConfigGroup is missing a cn (unexpected, entry ignored).");
					continue;
				}

				// Get associated protocol
				LDAPAttribute protocol = guacConfigGroupEntry.getAttribute("guacConfigProtocol");
				if (protocol == null) {
					logger.warn("guacConfigGroup \"{}\" is missing the " + "required \"guacConfigProtocol\" attribute (entry ingnored).", cn.getStringValue());
					continue;
				}

				// Set protocol
				GuacamoleConfiguration config = new GuacamoleConfiguration();
				config.setProtocol(protocol.getStringValue());

				// Get parameters, if any
				LDAPAttribute parameterAttribute = guacConfigGroupEntry.getAttribute("guacConfigParameter");
				processGuacConfigGroupParameters(parameterAttribute, config);

				// Store connection using CN as name && DN as identifier
				String name = cn.getStringValue();
				String identifier = guacConfigGroupEntry.getDN();
				Connection connection = new SimpleConnection(name, identifier, config);
				connection.setParentIdentifier(LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP); // May be overridden when creating connection groups
				connections.put(connection.getIdentifier(), connection);
			}
			
			return connections; // Return map of all connections
			
		} catch (LDAPException e) {
			throw new GuacamoleServerException("Error while processing guac configuration group LDAP entry.", e);
		}

	}
    
	/**
	 * Create the connections from the given guac config groups
	 * @param ldapConnection
	 *     The LDAP connection to use, bind with the default bind DN,
	 *     i.e. the technical user to query the LDAP directory service
	 * @param user
	 *     The authenticated user
	 * @param guacConfigGroups
	 * @return
	 *     The connections for the given guac config groups
	 * @throws GuacamoleException
	 */
	protected Map<String, Connection> getConnections(LDAPConnection ldapConnection, AuthenticatedUser user, String[] guacConfigGroups) throws GuacamoleException {
		Map<String, Connection> connections = new HashMap<String, Connection>();
		for (String guacConfigGroup : guacConfigGroups) {
			LDAPSearchResults guacConfigGroupsSearchResult = ldapsearchGuacConfigGroup(ldapConnection, guacConfigGroup);
			
			if (guacConfigGroupsSearchResult == null) continue; // Group not found ... just ignore

			connections.putAll(processGuacConfigGroupLdapEntries(guacConfigGroupsSearchResult));
		}
		return connections; // Return map of all connections
	}

    /**
     * Returns all Guacamole connections accessible to the authenticated user
     * @param ldapConnection
     *     The current connection to the LDAP server, associated with the
     *     current user.
     * @param user
     *     The authenticated user. 
     * 
     * @return
     *     All connections accessible to the authenticated user by the guac
     *     config groups he is a member of.
     *     
     *     The result is a map of connection identifier to
     *     corresponding connection object.
     *
     * @throws GuacamoleException
     *     If an error occurs preventing retrieval of connections.
     */
    public Map<String, Connection> getConnections(LDAPConnection ldapConnection, AuthenticatedUser user) throws GuacamoleException {

        try {
        	
        	LDAPSearchResults usersGroupsSearchResult = ldapsearchUsersGroups(ldapConnection, user);

            Map<String, Connection> connections = new HashMap<String, Connection>();
            
            String username = user.getCredentials().getUsername();

            if (usersGroupsSearchResult == null) {
            	logger.info("No groups for user [" + username + "] found => no connections.");
            	return connections;
            }
            
            // Get groups of user given by credentials (we take the values of all returned attributes as groups)
            while (usersGroupsSearchResult.hasMore()) {
                LDAPEntry userEntry = usersGroupsSearchResult.next();

                // Get groups by extracting the values of all attributes in the given entry
                for (@SuppressWarnings("unchecked") Iterator<LDAPAttribute> attrIter = userEntry.getAttributeSet().iterator(); attrIter.hasNext();) {
                    LDAPAttribute attr = attrIter.next();
                    String[] groups = attr.getStringValueArray();
                    if (groups.length > 0) {
                        connections.putAll(getConnections(ldapConnection, user, groups));
                    }
                    else {
                        logger.info("The user `" + username +  "' has no values in the attribute: [" + attr.getName() + "]");
                    }
                }
            }
            
            return connections;

        }
        catch (LDAPException e) {
            throw new GuacamoleServerException("Error while iterating guac configuration groups.", e);
        }

    }

}
