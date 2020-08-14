package revsyncghidra;

import java.util.*;
import java.util.Map.Entry;
import java.nio.*;

import ghidra.program.model.address.Address;
import ghidra.util.Msg;

public class Comments {
	protected static String delimiter = "\u0081" + "\n";
	protected static String badCharsXML1 = "[^\u0009\r\n\u0020-\uD7FF\uE000-\uFFFD\ud800\udc00-\udbff\udfff]";
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
			this.cmt = cmt.replaceAll(badCharsXML1,"");
		}

		public int compareTo(Object o) {
			Cmt c = (Cmt)o;
			return (int)(timestamp - c.timestamp);
		}
		
		public String toString() {
			return fmtuser(user) + cmt;
		}
	}
	
	public Comments(RevSyncGhidraPlugin f) {
		frontend = f;
	}
	
	public String set(Address ea, String user, String cmt, Long timestamp) {
		String result = new String();
		TreeMap<String,Cmt> newMap = comments.get(ea);
		
		if (newMap == null) {
			newMap = new TreeMap<String,Cmt>();
		}
		
		if ((cmt != null) && (!cmt.isBlank()))
		{
			newMap.put(user, new Cmt(timestamp, user, cmt));
		}
		else
		{
			newMap.remove(user);
		}
		comments.put(ea, newMap);
		
		StringJoiner s = new StringJoiner(delimiter);
		for (Cmt e : newMap.values()) {
			s.add(e.toString());
		}
		result = s.toString();
		
		text.put(ea, result);
		if (result.isBlank()){
			return null;
		}
		return result;
	}
	
	public String get_comment_at_addr(Address ea) {
		return text.get(ea);
	}
	
	public String parse_comment_update(Address ea, String user, String cmt) throws NoChange {
		TreeMap<String,Cmt> oldMap = comments.get(ea);
		String oldText = text.get(ea);
		Cmt oldCmt = null;
		String newCmtText = null;
		
		if (cmt == null){
			return "";
		}
		
		if (oldText != null) {
			if (oldText.equals(cmt) || oldText.equals(cmt.trim())) {
				throw new NoChange("No change - whole comment");
			}
		}
		
		cmt = cmt.strip();
				
		String [] splitCmts = cmt.split(delimiter);
		for (String c : splitCmts) {
			if (c.startsWith(fmtuser(user))) {
				newCmtText = c.split("] ")[1];
				break;
			}
		}
		if (newCmtText == null) {
			newCmtText = splitCmts[splitCmts.length-1];			
		}
		
		if (oldMap != null) {
			oldCmt = oldMap.get(user);
			if (oldCmt != null) {
				if (oldCmt.cmt.strip().equals(newCmtText.strip())) {
					throw new NoChange("No change - for user");
				}
			}
		}
				
		return newCmtText;
	}
	
	public String test() {
		return delimiter;
	}
	
	
}

