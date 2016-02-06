package io.github.kc14.guacamole.auth.ldap389ds.connection;

import static io.github.kc14.com.novell.ldap.util.DNHelper.getRDNs;

import java.util.Collections;
import java.util.Map;
import java.util.Vector;

import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.net.auth.Connection;
import org.glyptodon.guacamole.net.auth.ConnectionGroup;
import org.glyptodon.guacamole.net.auth.Directory;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroup;
import org.glyptodon.guacamole.net.auth.simple.SimpleConnectionGroupDirectory;
import org.glyptodon.guacamole.net.auth.simple.SimpleDirectory;

import com.google.inject.Inject;
import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

import io.github.kc14.guacamole.auth.ldap389ds.config.ConfigurationService;
import net.sourceforge.guacamole.net.auth.ldap389ds.LDAP389dsAuthenticationProvider;

public class ConnectionTreeContext {

    /**
     * Service for retrieving LDAP server configuration information.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Directory containing all Connection objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<Connection> connectionMap;

    /**
     * Directory containing all ConnectionGroup objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<ConnectionGroup> folderMap;

	public void putConnections(Map<String, Connection> connections) throws GuacamoleException {
        // Create a simple read-only <i>connection</i> directory from all connections
        connectionMap = new SimpleDirectory<Connection>(connections);

        // Create a simple read-only <i>connection group</i> directory with an empty root group
        SimpleConnectionGroupDirectory folderMap = createfolderMap();
        
        // Add prefix, so we have configBaseDN as ROOT even when no connections exist
    	DN configBaseDN = new DN(confService.getConfigurationBaseDN());
    	putFolders(folderMap, configBaseDN);

        // Build tree of connection groups from the DNs (= identifier) of the connections
		for (Connection connection : connections.values()) {
			putConnection (folderMap, connection);
		}

        this.folderMap = folderMap;
	}

	static private SimpleConnectionGroupDirectory createfolderMap() throws GuacamoleException {
		return new SimpleConnectionGroupDirectory(Collections.singleton(createRootFolder()));
	}

	private static ConnectionGroup createRootFolder() {
		// Root group is initially empty
		return new SimpleConnectionGroup(
            LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP,
            LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP,
            Collections.<String>emptyList(),
            Collections.<String>emptyList()
        );
	}

    /**
     * Put a Connection into a Tree of Connection Groups alias Folders
     * <p>
     * We take the DN of a connection and convert every RDN into a
     * corresponding connection folder pointing to its parent and
     * containing its sub connection folders and connections.
     * <p>
     * The CN will always be taken as the name for a group node itself.
     * <p>
     * We do NOT insert Connections into the Connection Directory. We
     * presume that all connections are already in the Connection Directory.
     * We just insert connections into their corresponding Connection Group!
     * <p>
     * 
     * Preconditions:
     * <ul>
     * <li> all connections exist already in the Connection Directory 
     * <li> folderMap is not null
     * <li> folderMap has an entry with the name "ROOT" which is not null
     * <li> connection is not null
     * </ul>
     * 
     * @param folderMap - newly created groups get inserted into this directory
     * @param connection - the connection to insert into the tree of connection groups
     * @throws GuacamoleException
     */
    private static void putConnection(SimpleConnectionGroupDirectory folderMap, Connection connection) throws GuacamoleException {
    	// Preconditions
    	assert folderMap != null : "Pre: Connection Group Directory exits!";
    	assert folderMap.get(LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP) != null : "Pre: Connection Group Directory Contains Group with id `ROOT'";	
    	assert connection != null : "Pre: Connection exists!";
    	// Code
    	ConnectionGroup folder = putConnectionFolders(folderMap, connection);
		putConnection(folder, connection);
	}

	/**
	 * This method converts the RDNs in the DN of a connection into Folders
	 * <p>
	 * We follow the simple pattern of conversion from a path to tree nodes
	 * for the ADT tree
	 * <p>
	 * Here is the algorithm:
	 * First we use the RDN as Folder Name. The walk along the list of RDNs
	 * <pre>
	 * <code>
	 * folder = ROOT;
	 * for each RDN in DN(Connection):
	 *     if folder contains RDN then
	 *         folder := folder.get(RDN)
	 *     else
	 *         create childFolder with name of RDN
	 *         folder.add(childFolder)
	 *         folder := childFolder
	 * folder.add(connection)
	 * </code>
	 * </pre>
	 * 
	 * @param folderMap
	 * @param connection
	 * @return
	 * @throws GuacamoleException
	 */
	private static ConnectionGroup putConnectionFolders(SimpleConnectionGroupDirectory folderMap, Connection connection) throws GuacamoleException {
    	DN connectionDN = new DN(connection.getIdentifier());
    	DN folderDN = connectionDN.getParent(); // Group is baseDN
    	return putFolders(folderMap, folderDN);
	}

	private static ConnectionGroup putFolders(SimpleConnectionGroupDirectory folderMap, DN folderDN) throws GuacamoleException {
		Vector<RDN> folderRDNs = getRDNs(folderDN);
    	Collections.reverse(folderRDNs); // Start with root rdn
    	ConnectionGroup folder = folderMap.get(LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP); // Put into ROOT
    	DN currentFolderDN = new DN();
    	for (RDN currentFolderRDN : folderRDNs) {
    		currentFolderDN.addRDN(currentFolderRDN);
    		String childFolderName = currentFolderRDN.toString();
    		String childFolderIdentifier = currentFolderDN.toString();
    		folder = putFolder (folderMap, folder, childFolderName, childFolderIdentifier);
    	}
    	return folder;
	}

	private static ConnectionGroup putFolder(SimpleConnectionGroupDirectory folderMap, ConnectionGroup folder, String childFolderName, String childFolderIdentifier) throws GuacamoleException {
		String folderIdentifier = folder.getIdentifier();
		ConnectionGroup childFolder = folderMap.get(childFolderIdentifier);
		if (childFolder != null) return childFolder; // Found group => return it
		// Create group
		SimpleConnectionGroup newFolder = new SimpleConnectionGroup(
			childFolderName,
			childFolderIdentifier,
			Collections.<String>emptyList(),
			Collections.<String>emptyList()
		);
		newFolder.setParentIdentifier(folderIdentifier);
		folder.getConnectionGroupIdentifiers().add(childFolderIdentifier);
		folderMap.putConnectionGroup(newFolder); // Add to directory
		return newFolder;
	}

	private static void putConnection(ConnectionGroup folder, Connection connection) throws GuacamoleException {
    	String folderIdentifier = folder.getIdentifier();
    	connection.setParentIdentifier(folderIdentifier);
    	folder.getConnectionIdentifiers().add(connection.getIdentifier());
	}

    public ConnectionGroup getRootFolder() throws GuacamoleException {
    	DN configBaseDN = new DN(confService.getConfigurationBaseDN());
        return getFolderMap().get(configBaseDN.toString()); // Return config base as root
        // return getFolderMap().get(LDAP389dsAuthenticationProvider.ROOT_CONNECTION_GROUP);
    }

    public Directory<Connection> getConnectionMap() {
		return connectionMap;
	}

	public Directory<ConnectionGroup> getFolderMap() {
		return folderMap;
	}
}
