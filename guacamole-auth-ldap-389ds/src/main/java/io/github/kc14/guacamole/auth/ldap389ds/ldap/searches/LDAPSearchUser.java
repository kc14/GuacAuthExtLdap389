package io.github.kc14.guacamole.auth.ldap389ds.ldap.searches;

import java.net.MalformedURLException;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Credentials;
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

public class LDAPSearchUser {

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
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(LDAPSearchUser.class);
    
    // Example LDAP URL: ldap:///uid=${username},ou=People,dc=vuvufone,dc=localdomain?base?uid?(objectClass=posixAccount)
    public LDAPSearchResults searchUserByCredentials(LDAPConnection ldapConnection, Credentials credentials) throws GuacamoleException, LDAPException, MalformedURLException {
        String ldapUrlAsString = confService.getLdapUrlUserByCredentials();
        String ldapUrlAsStringWithMacrosExpanded = MacroPreProcessor.expandStandardTokens(credentials, ldapUrlAsString);
        logger.info("ldap url expanded: [" + ldapUrlAsStringWithMacrosExpanded + "]");
        LDAPUrl ldapUrl = new LDAPUrl(ldapUrlAsStringWithMacrosExpanded);
        LDAPSearchResults ldapSearchResults = LDAPSearch.search(ldapConnection, ldapUrl);
        return ldapSearchResults;
	}

}
