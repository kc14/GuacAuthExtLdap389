package io.github.kc14.guacamole.auth.ldap389ds.ldap.searches;

import java.net.MalformedURLException;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.net.auth.AuthenticatedUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPUrl;

import io.github.kc14.guacamole.auth.ldap389ds.config.ConfigurationService;
import io.github.kc14.guacamole.auth.ldap389ds.ldap.EscapingService;
import io.github.kc14.guacamole.auth.ldap389ds.utils.MacroPreProcessor;

public class LDAPSearchUsersGroups {
    
    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(LDAPSearchUsersGroups.class);    
    
    /**
     * Service for retrieving LDAP server configuration information.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Service for escaping parts of LDAP queries.
     */
    @Inject
    private EscapingService escapingService;    
    
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
     * @throws MalformedURLException 
     * @throws LDAPException 
     */
    public LDAPSearchResults searchUsersGroups(LDAPConnection ldapConnection, AuthenticatedUser user) throws GuacamoleException, MalformedURLException, LDAPException {
        String ldapUrlAsString = confService.getLdapUrlUsersGroups();
        String ldapUrlAsStringWithMacrosExpanded = MacroPreProcessor.expandStandardTokens(user.getCredentials(), ldapUrlAsString);
        logger.info("ldap url expanded: [" + ldapUrlAsStringWithMacrosExpanded + "]");
        LDAPUrl ldapUrl = new LDAPUrl(ldapUrlAsStringWithMacrosExpanded);
        LDAPSearchResults ldapSearchResults = LDAPSearch.search(ldapConnection, ldapUrl);
        return ldapSearchResults;
    }

}
