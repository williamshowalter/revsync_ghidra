# Errata

Eclipse might not properly import lib/ files (.jar files) when it launches Ghidra through Eclipse. The fix for this is to go to:

Run -> Run Configurations -> Ghidra -> RevSyncGhidra -> Classpath:

Make sure that the libraries you want are not in Bootstrap Entries, but instead are under User Entries.
