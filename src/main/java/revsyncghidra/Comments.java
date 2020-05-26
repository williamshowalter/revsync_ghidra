package revsyncghidra;

import java.util.*;
import java.nio.*;

import ghidra.program.model.address.Address;
import ghidra.util.Msg;

public class Comments {
	protected String delimiter = ((char)0x1f) + "\n";
	private TreeMap<Address,TreeMap<String,Cmt>> comments = new TreeMap<Address,TreeMap<String,Cmt>>();
	private TreeMap<Address,String> text = new TreeMap<Address,String>();
	protected RevSyncGhidraPlugin frontend;
	
	protected static String fmtuser(String user) {
		return "[" + user + "] ";
	}
	
	public static class NoChange extends Exception {
		public NoChange() {}
		public NoChange(String m) {super(m);}
	}
	
	public static class Cmt implements Comparable {
		public long timestamp;
		public String user;
		public String cmt;

		public Cmt() {}

		public Cmt(long timestamp, String user, String cmt) {
			this.timestamp = timestamp;
			this.user = user;
			this.cmt = cmt;
		}

		public int compareTo(Object o) {
			Cmt c = (Cmt)o;
			return (int)(timestamp - c.timestamp);
		}
	}
	
	public Comments(RevSyncGhidraPlugin f) {
		frontend = f;
	}
	
	public String set(Address ea, String user, String cmt, Long timestamp) {
		frontend.consolePrint("Comment at ea: " + ea.toString() + " - User: " + user + " - Cmt: " + cmt + " - ts: " + timestamp.toString());
		return new String();
	}
	
	public String get_comment_at_addr(Address ea) {
		return new String();
	}
	
	public String test() {
		return delimiter;
	}
	
	
}

