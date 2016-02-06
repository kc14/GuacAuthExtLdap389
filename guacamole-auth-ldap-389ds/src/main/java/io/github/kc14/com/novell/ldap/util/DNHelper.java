package io.github.kc14.com.novell.ldap.util;

import java.util.ListIterator;
import java.util.Vector;

import com.novell.ldap.util.DN;
import com.novell.ldap.util.RDN;

public abstract class DNHelper {

	@SuppressWarnings("unchecked")
	public static Vector<RDN> getRDNs (DN dn) {
		return (Vector<RDN>)dn.getRDNs();
	}
	
	public static boolean isDescendantOf(DN descendantDN, DN forfatherDN){
		Vector<RDN> descendantRDNs = getRDNs(descendantDN);
		Vector<RDN> forfatherRDNs = getRDNs(forfatherDN);
        int descendantRDNIdx = descendantRDNs.size() - 1; // Index to an RDN of the ContainedDN
        int forfatherRDNIdx = forfatherRDNs.size() - 1; // Index to an RDN of the ContainerDN
        // Search from the end of the contained DN for an RDN that matches the end RDN of containerDN.
        while (!((RDN)descendantRDNs.get(descendantRDNIdx--)).equals((RDN)forfatherRDNs.get(forfatherRDNIdx))){
            if (descendantRDNIdx <= 0) return false; // If the end RDN of forfather DN does not have any equal RDN but the last in descendant RDN, then descendant DN is not a descendant of forfather DN
        }
        forfatherRDNIdx--;  // Avoid a redundant compare
        for (/* descendantRDNIdx, forfatherRDNIdx */; descendantRDNIdx >= 0 && forfatherRDNIdx >= 0; descendantRDNIdx--, forfatherRDNIdx--){ // Step further backwards to verify that all RDNs in forfather DN exist in descendant DN
            if (!((RDN)descendantRDNs.get(descendantRDNIdx)).equals((RDN)forfatherRDNs.get(forfatherRDNIdx))) return false;
        }
        if (descendantRDNIdx < 0 && forfatherRDNIdx < 0) return false; // The DNs are identical and thus the descendant DN is not a descendant of forfather DN (compare equal to 0 was wrong, since i=-1 & j=-1 after the loop if RDNs are equal)
        return true;
    }

	public static void subtractRDNsFromBack (Vector<RDN> minuendRDNs, Vector<RDN> subtrahendRDNs) {
		ListIterator<RDN> minuend = minuendRDNs.listIterator(minuendRDNs.size());
		ListIterator<RDN> subtrahend = subtrahendRDNs.listIterator(subtrahendRDNs.size());
		// Compare RDNs from back 
		while (minuend.hasPrevious() && subtrahend.hasPrevious()) {
			RDN minuendRDN = minuend.previous();
			RDN subtrahendRDN = subtrahend.previous();
			if (minuendRDN.equals(subtrahendRDN) == false) break; 
			minuend.remove();
		}
	}
	
	public static void addRDNs(DN dn, Vector<RDN> rdns) {
		for (RDN rdn : rdns) {
			dn.addRDN(rdn);
		}
	}
	
	public static DN toDN(Vector<RDN> rdns) {
		DN dn = new DN();
		addRDNs(dn, rdns);
		return dn;
	}

}
