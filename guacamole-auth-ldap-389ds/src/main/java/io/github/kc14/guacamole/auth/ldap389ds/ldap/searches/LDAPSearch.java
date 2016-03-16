package io.github.kc14.guacamole.auth.ldap389ds.ldap.searches;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPUrl;

public class LDAPSearch {

    public static LDAPSearchResults search(LDAPConnection ldapConnection, LDAPUrl ldapUrl) throws LDAPException {
        LDAPSearchResults ldapSearchResults = null;
        if (ldapUrl.getHost().isEmpty()) { // Use given ldap connection
            ldapSearchResults = searchLocal(ldapConnection, ldapUrl);
        }
        else { // Open new ldap connection given in url
            ldapSearchResults = LDAPConnection.search(ldapUrl);
        }
        return ldapSearchResults;
    }

    private static LDAPSearchResults searchLocal(LDAPConnection ldapConnection, LDAPUrl ldapUrl) throws LDAPException {
        LDAPSearchConstraints constraints = ldapConnection.getSearchConstraints();
        constraints.setBatchSize(0); // Must wait until all results arrive
        boolean typesOnlyIsFalse = false;
        LDAPSearchResults ldapSearchResults = ldapConnection.search(
                ldapUrl.getDN(),
                ldapUrl.getScope(),
                ldapUrl.getFilter(),
                ldapUrl.getAttributeArray(),
                typesOnlyIsFalse,
                constraints);
        return ldapSearchResults;
    }

}
