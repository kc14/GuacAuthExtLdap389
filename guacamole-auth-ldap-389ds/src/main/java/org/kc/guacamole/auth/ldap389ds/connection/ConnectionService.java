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

package org.kc.guacamole.auth.ldap389ds.connection;

import com.google.inject.Inject;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.util.DN;

import net.sourceforge.guacamole.net.auth.ldap389ds.LDAP389dsAuthenticationProvider;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnection;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.kc.guacamole.auth.ldap389ds.ConfigurationService;
import org.kc.guacamole.auth.ldap389ds.EscapingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static final List<String> GUAC_CONFIG_GROUP_ATTRIBUTES = new ArrayList<String>() {{
        add("cn");
        add("guacConfigProtocol");
        add("guacConfigParameter");
    }};

	/**
	 * Search for the authenticated user entry 
	 * 
	 * @param user
	 *     The authenticated user
	 * @param ldapConnection
	 *     The LDAP connection to use, bind with the default bind DN,
	 *     i.e. the technical user to query the LDAP directory service
	 * @return
	 * @throws GuacamoleException
	 */
	protected LDAPSearchResults ldapsearchUserEntryMemberOf(AuthenticatedUser user, LDAPConnection ldapConnection) throws GuacamoleException {
		
        String username = user.getCredentials().getUsername();
    	String userBaseDN = confService.getUserBaseDN();
        int searchScopeOne = LDAPConnection.SCOPE_ONE;
        String userObjectClass = confService.getUserObjectClass();
        String usernameAttribute = confService.getUsernameAttribute();
        String memberOfAttribute = confService.getUserMemberOfAttribute();
        String userSearchFilter = "(&(objectClass=" + userObjectClass + ")(" + escapingService.escapeLDAPSearchFilter(usernameAttribute) + "=" + username + "))";
        String attrMemberOf[] = { memberOfAttribute };
        boolean typesOnlyFalse = false;            

        try {

            // Get memberOf attribute of user given by credentials
            LDAPSearchResults userEntryMemberOfSearchResult = ldapConnection.search(userBaseDN, searchScopeOne, userSearchFilter, attrMemberOf, typesOnlyFalse);
            return userEntryMemberOfSearchResult;      

        }
        catch (LDAPException e) {
        	if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
        		logger.info("No user entry found for `" + username + "' at base DN `" + userBaseDN + "'");
        		return null;
        	}
            throw new GuacamoleServerException("Error while searching for guac configuration groups (i.e. memberOf-attribute: `" + memberOfAttribute + "') of user `" + username + "'.", e);
        }
	}
	
    /**
     * Check whether the given guac config group lives under the config base DN
     * 
     * @param guacConfigGroupDN
     * @return
     * @throws GuacamoleException
     */
    protected boolean isDescendantOfConfigBaseDN (DN guacConfigGroupDN) throws GuacamoleException {
		// Ensure that the guac config group lives under the configuration base DN
    	DN configBaseDN = new DN(confService.getConfigurationBaseDN());
    	if (guacConfigGroupDN.isDescendantOf(configBaseDN) == false) { // isDecendantOf does not work as expected				
			logger.warn(
					"guacConfigGroup \"{}\" is not an element of configuration base DN \"{}\" (entry ignored).",
					guacConfigGroupDN,
					configBaseDN);
			return false;
		}
    	return true;
    }
    
    /**
     * Check whether the given guac config group lives under the config base DN
     * 
     * @param guacConfigGroupDN
     * @return
     * @throws GuacamoleException
     */
    protected boolean isDescendantOfConfigBaseDN_simple (DN guacConfigGroupDN) throws GuacamoleException {
		// Ensure that the guac config group lives under the configuration base DN
    	DN configBaseDN = new DN(confService.getConfigurationBaseDN());
    	if (guacConfigGroupDN.toString().toLowerCase().endsWith(configBaseDN.toString().toLowerCase()) == false) {					
			logger.warn(
					"guacConfigGroup \"{}\" is not an element of configuration base DN \"{}\" (entry ignored).",
					guacConfigGroupDN,
					configBaseDN);
			return false;
		}
    	return true;
    }
    
    /**
     * Check if guac config group starts with configured prefix
     * 
     * @param guacConfigGroupDN
     * @return
     * @throws GuacamoleException
     */
    protected boolean startsWithConfigGroupPrefix(DN guacConfigGroupDN) throws GuacamoleException {
		boolean noTypesTrue = true;
		String[] explodedGuacConfigGroupDN = guacConfigGroupDN.explodeDN(noTypesTrue);
		String guacConfigGroupPrefix = confService.getGuacConfigGroupPrefix();
		if (explodedGuacConfigGroupDN.length == 0 || explodedGuacConfigGroupDN[0].toLowerCase().startsWith(guacConfigGroupPrefix.toLowerCase()) == false) {
			logger.warn(
					"guacConfigGroup \"{}\" does not have configured prefix \"{}\" (entry ignored).",
					guacConfigGroupDN,
					guacConfigGroupPrefix);
			return false;
		}
		return true;
    }
    
	/**
	 * LDAP search for the guac configuration group given as DN in guacConfigGroup
	 * @param guacConfigGroup
	 *     The DN of a guacConfigGroup as given in the memberOf-Attribute
	 *     of the posixAccount of the authenticated user
	 * @param ldapConnection
	 *     The LDAP connection to use, bind with the default bind DN,
	 *     i.e. the technical user to query the LDAP directory service
	 * @return
	 *     The LDAP search result containing the base entry for the given guac config group
	 *     retrieving the attributes given in GUAC_CONFIG_GROUP_ATTRIBUTES
	 * @throws GuacamoleException
	 */
	protected LDAPSearchResults ldapsearchGuacConfigGroup(String guacConfigGroup, LDAPConnection ldapConnection)
			throws GuacamoleException {
		DN guacConfigGroupDN = new DN(guacConfigGroup);

		// Is guac config group a descendant of configuration base DN?
		if (isDescendantOfConfigBaseDN_simple(guacConfigGroupDN) == false) return null;
	
		// Check if guac config group starts with configured prefix
		if (startsWithConfigGroupPrefix(guacConfigGroupDN) == false) return null;
		
		// Search given guacamole config group
		String guacConfigGroupSearchBaseDN = guacConfigGroup;
		int searchScopeBase = LDAPConnection.SCOPE_BASE;
		String guacObjectClass = confService.getGuacConfigGroupObjectClass();
		String guacConfigGroupSearchFilter = "(objectClass=" + guacObjectClass + ")";
		String[] guacConfigAttrs = new String[GUAC_CONFIG_GROUP_ATTRIBUTES.size()];
		guacConfigAttrs = GUAC_CONFIG_GROUP_ATTRIBUTES.toArray(guacConfigAttrs);
		boolean typesOnlyFalse = false;
		try {
			LDAPSearchResults guacConfigGroupsSearchResult = ldapConnection.search(guacConfigGroupSearchBaseDN, searchScopeBase, guacConfigGroupSearchFilter, guacConfigAttrs, typesOnlyFalse);
			return guacConfigGroupsSearchResult;
		} catch (LDAPException e) {
			throw new GuacamoleServerException("Error while searching for guac configuration group `" + guacConfigGroup + "'.", e);
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
	 * 
	 * @param guacConfigGroupsSearchResult
	 *     The LDAP search result containing the guac config group entries to process
	 * @param ldapConnection
	 *     The LDAP connection to use, bind with the default bind DN,
	 *     i.e. the technical user to query the LDAP directory service
	 * @return
	 *     The connections configured by the given guac config groups 
	 * @throws GuacamoleServerException
	 */
	protected Map<String, Connection> processGuacConfigGroupLdapEntries(LDAPSearchResults guacConfigGroupsSearchResult, LDAPConnection ldapConnection) throws GuacamoleServerException {
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

				// Store connection using cn for both identifier and name
				String name = cn.getStringValue();
				String identifier = guacConfigGroupEntry.getDN();
				Connection connection = new SimpleConnection(name, identifier, config);
				connection.setParentIdentifier(LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP);
				connections.put(connection.getIdentifier(), connection);
			}
			
			return connections; // Return map of all connections
			
		} catch (LDAPException e) {
			throw new GuacamoleServerException("Error while processing guac configuration group LDAP entry.", e);
		}

	}
    
	/**
	 * Create the connections from the given guac config groups
	 * @param user
	 *     The authenticated user
	 * @param guacConfigGroups
	 * @param ldapConnection
	 *     The LDAP connection to use, bind with the default bind DN,
	 *     i.e. the technical user to query the LDAP directory service
	 * @return
	 *     The connections for the given guac config groups
	 * @throws GuacamoleException
	 */
	protected Map<String, Connection> getConnections(AuthenticatedUser user, String[] guacConfigGroups, LDAPConnection ldapConnection) throws GuacamoleException {
		Map<String, Connection> connections = new HashMap<String, Connection>();
		for (String guacConfigGroup : guacConfigGroups) {
			LDAPSearchResults guacConfigGroupsSearchResult = ldapsearchGuacConfigGroup(guacConfigGroup, ldapConnection);
			
			if (guacConfigGroupsSearchResult == null) continue; // Group not found ... just ignore

			connections.putAll(processGuacConfigGroupLdapEntries(guacConfigGroupsSearchResult, ldapConnection));
		}
		return connections; // Return map of all connections
	}

    /**
     * Returns all Guacamole connections accessible to the authenticated user
     * 
     * @param user
     *     The authenticated user. 
     *
     * @param ldapConnection
     *     The current connection to the LDAP server, associated with the
     *     current user.
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
    public Map<String, Connection> getConnections(AuthenticatedUser user, LDAPConnection ldapConnection)
            throws GuacamoleException {

        try {
        	
        	LDAPSearchResults userEntryMemberOfSearchResult = ldapsearchUserEntryMemberOf(user, ldapConnection);

            Map<String, Connection> connections = new HashMap<String, Connection>();
            
            String username = user.getCredentials().getUsername();
            String memberOfAttribute = confService.getUserMemberOfAttribute();

            if (userEntryMemberOfSearchResult == null) {
            	logger.info("User `" + username + "' not found => no connections.");
            	return connections;
            }
            
            // Get memberOf attribute of user given by credentials
            while (userEntryMemberOfSearchResult.hasMore()) {
                LDAPEntry userEntry = userEntryMemberOfSearchResult.next();

                // Get member of (memberOf-Attribute)
                LDAPAttribute memberOf = userEntry.getAttribute(memberOfAttribute);
                if (memberOf == null) {
                    logger.info("The user `" + username +  "' has no guacConfigGroups.");
                    continue;
                }
                
                // Search for the guac config groups
                String[] guacConfigGroups = memberOf.getStringValueArray();
                connections.putAll(getConnections(user, guacConfigGroups, ldapConnection));
                            	
            }
            
            return connections;

        }
        catch (LDAPException e) {
            throw new GuacamoleServerException("Error while iterating guac configuration groups.", e);
        }

    }

}
