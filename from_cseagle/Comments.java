
import java.util.*;
import ghidra.program.model.address.*;

public class Comments {

   public static class NoChange extends Exception {
      public NoChange() {}
      public NoChange(String m) {super(m);}
   }

   /* test class in lieu of Ghidra's Address class */
/*
   public static class Address implements Comparable {
      public long offset;
      public Address(long addr) {offset = addr;}
      public long getOffset() {return offset;}
      public int compareTo(Object o) {
         Address a = (Address)o;
         return (int)(offset - a.offset);
      }
   }
*/
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

   public TreeMap<String,Cmt> empty = new TreeMap<String,Cmt>();
   public TreeMap<Address,TreeMap<String,Cmt>> comments = new TreeMap<Address,TreeMap<String,Cmt>>();
   public TreeMap<Address,String> text = new TreeMap<Address,String>();
   public String delimiter = ((char)0x1f) + "\n";

   public static String fmtuser(String user) {
       return "[" + user + "]";
   }

   public Comments() {
   }

   public String set(Address ea, String user, String cmt, long timestamp) {
      if (cmt.trim().length() > 0) {
         if (!comments.containsKey(ea)) {
            comments.put(ea, new TreeMap<String,Cmt>());
         }
         comments.get(ea).put(user, new Cmt(timestamp, user, cmt));
      }
      else {
         if (comments.containsKey(ea)) {
            comments.get(ea).remove(user);
         }
      }
      TreeSet<Cmt> cmts = new TreeSet<Cmt>(comments.get(ea).values());
      String result = "";
      for (Cmt c : cmts) {
         if (result.length() > 0) {
            result += delimiter;
         }
         result += fmtuser(c.user) + c.cmt;
      }
      text.put(ea, result);
      return result;
   }

   public String get_comment_at_addr(Address ea) {
      return text.get(ea);
   }

   public String parse_comment_update(Address ea, String user, String cmt) throws NoChange {
      if (cmt == null || cmt.length() == 0) {
         return "";
      }
      if (cmt.equals(text.getOrDefault(ea, ""))) {
         throw new NoChange();
      }
      String f = fmtuser(user);
      String[] cmts = cmt.split(delimiter);
      String new_cmt = null;
      for (int i = 0; i < cmts.length; i++) {
         if (cmts[i].startsWith(f)) {
            System.err.println("zz: " + cmts[i]);
            String[] xx = cmts[i].split("]", 2);
            System.err.println(xx.length);
            new_cmt = cmts[i].split("]", 2)[1];
            break;
         }
      }
      if (new_cmt == null) {
         // Assume new comments are always appended
         String[] split = cmt.split(delimiter);
         new_cmt = split[split.length - 1];
      }
      Cmt old = comments.getOrDefault(ea, empty).getOrDefault(user, new Cmt());
      if (old.timestamp != 0) {
         if (old.cmt.trim().equals(new_cmt.trim())) {
            throw new NoChange();
         }
      }
      return new_cmt;
   }

/*
   public static long ts = 1;
   public static Comments test = new Comments();

   public static void add(Address addr, String user, String comment) {
      ts += 1;
      System.err.println(String.format("[+] 0x%x [%s] %s", addr.getOffset(), user, comment));
      test.set(addr, user, comment, ts);
      System.err.println(String.format("Comment at 0x%x:\n%s", addr.getOffset(), test.get_comment_at_addr(addr)));
      System.err.println();
   }

   public static void main(String args[]) throws Exception {
       Address ea = new Address(0x1000);
       add(ea, "alice", "hello from alice");
       add(ea, "bob", "hello from bob");
       add(ea, "alice", "update from alice");
   
       String text = test.get_comment_at_addr(ea);
       System.err.println("----------------------------------------");
       String split[] = text.split(test.delimiter);
       for (int i = 0; i < split.length; i++) {
           String line = split[i];
           if (line.contains(fmtuser("alice"))) {
               split[i] += " added stuff";
               String update = String.join(test.delimiter, split);
               System.err.println("[-] update:\n" + update);
               String changed = test.parse_comment_update(ea, "alice", update);
               System.err.println("[-] changed text:\n" + changed);
               System.err.println("[-] set:");
               add(ea, "alice", changed);
               break;
           }
       }
   
       System.err.println("----------------------------------------");
       String changed = test.parse_comment_update(ea, "alice", "replaced all text");
       add(ea, "alice", changed);
   
       System.err.println("----------------------------------------");
       try {
           text = test.get_comment_at_addr(ea);
           test.parse_comment_update(ea, "alice", text);
           System.err.println("[!] oh no, change detected!");
       } catch (NoChange nc) {
           System.err.println("[+] no change detected");
       }
   
       System.err.println("----------------------------------------");
       System.err.println("empty update: " + test.parse_comment_update(ea, "alice", ""));
   
       System.err.println();

   }
*/

}
