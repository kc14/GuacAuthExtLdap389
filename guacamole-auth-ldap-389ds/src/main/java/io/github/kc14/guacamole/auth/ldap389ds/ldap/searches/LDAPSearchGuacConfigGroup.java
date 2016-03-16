package io.github.kc14.guacamole.auth.ldap389ds.ldap.searches;

import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;

import org.glyptodon.guacamole.GuacamoleException;
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

public class LDAPSearchGuacConfigGroup {
    
    /**
     * The name of the username token added via addStandardTokens().
     */
    private static final String GUAC_CONFIG_GROUP_TOKEN = "GUAC_CONFIG_GROUP";
    
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
     * @throws MalformedURLException 
     * @throws LDAPException 
     */
    public LDAPSearchResults ldapsearchGuacConfigGroup(LDAPConnection ldapConnection, String guacConfigGroup) throws GuacamoleException, MalformedURLException, LDAPException {
        String ldapUrlAsString = confService.getLdapUrlSearchGuacConfigGroup();
        Map<String, String> tokens = new HashMap<String, String>(1);
        tokens.put(GUAC_CONFIG_GROUP_TOKEN, guacConfigGroup);
        String ldapUrlAsStringWithMacrosExpanded = MacroPreProcessor.expandTokens(tokens, ldapUrlAsString);
        logger.info("ldap url expanded: [" + ldapUrlAsStringWithMacrosExpanded + "]");
        LDAPUrl ldapUrl = new LDAPUrl(ldapUrlAsStringWithMacrosExpanded);
        LDAPSearchResults ldapSearchResults = LDAPSearch.search(ldapConnection, ldapUrl);
        return ldapSearchResults;        
    }

}
