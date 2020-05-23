
import ghidra.program.model.listing.Program;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.plugin.importer.NewLanguagePanel;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;

/*
extends ghidra.app.plugin.ProgramPlugin implements RevsyncFrontend

override
 * <LI> <code>programActivated(Program)</code>              maybe reattach if previously associated
 * <LI> <code>programDeactivated(Program)</code>              detach from server
 * <LI> <code>locationChanged(ProgramLocation)</code>    handle change notifications

parent tool needs to be CodeBrowser
super(CodeBrowser, true, false)

*/

public class GhidraFrontend extends ghidra.app.plugin.ProgramPlugin implements RevsyncFrontend {

   private FlatProgramAPI flat;
   private Program prog;
   public String fhash;
   public Comments comments;
   
   public static String[] ghidra_reserved_prefix = {
       "SUB_", "FUN_", "locret_", "LOC_", "off_", "seg_", "asc_", "byte_", "word_",
       "dword_", "qword_", "byte3_", "xmmword_", "ymmword_", "packreal_",
       "flt_", "dbl_", "tbyte_", "stru_", "custdata_", "algn_", "unk_"
   };

   public RevSyncConfig conf;
   public RevsyncClient client;

   public long get_can_addr(Address addr) {
      //"""Convert an Effective Address to a canonical address."""
      return addr.getOffset() - prog.getImageBase().getOffset();
   }
   
   public long get_ea(Address addr) {
      //"""Get Effective Address from a canonical address."""
      return addr.getOffset() + prog.getImageBase().getOffset();
   }

   public void onmsg_safe(String key, TreeMap<String,Object> data, boolean replay) {
      try {
         onmsg(key, data, replay);
      } catch (Exception ex) {
         System.err.println(String.format("error during callback for %s: %s", data.get("cmd"), ex.toString()));
         ex.printStackTrace();
      }
   }
   
   public void onmsg_safe(String key, TreeMap<String,Object> data) {
      onmsg_safe(key, data, false);
   }

   public void onmsg(String key, TreeMap<String,Object> data, boolean replay) {
      if (!key.equals(fhash)) {
         System.err.println("revsync: hash mismatch, dropping command");
         return;
      }
   }
   
   public void onmsg(String key, TreeMap<String,Object> data) {
      onmsg(key, data, false);
   }

   public GhidraFrontend(Program p) {
      prog = p;
      flat = new FlatProgramAPI(p);
      fhash = p.getExecutableSHA256().toUpperCase();
      conf = new RevsyncConfig();
      client = new RevsyncClient(this, conf);
      comments = new Comments();
   }

	public void run() throws Exception {
   }

   public void publish(TreeMap<String,Object> data, boolean send_uuid, boolean perm) {
      if (fhash != null) {
         client.publish(fhash, data, send_uid, perm);
      }
   }

   public void publish(TreeMap<String,Object> data, boolean send_uuid) {
      publish(data, send_uid, true);
   }

   public void publish(TreeMap<String,Object> data) {
      publish(data, true, true);
   }


	/**
	 * Subclass should override this method if it is interested when programs become inactive.
	 * Note: this method is called in response to a ProgramActivatedPluginEvent and there is 
	 * a currently active program.
	 * 
	 * At the time this method is called, 
	 * the "currentProgram" variable will be set the 
	 * new active program or null if there is no new active program.
	 * 
	 * @param program the old program going inactive.
	 */
	protected void programDeactivated(Program program) {
	   if (fhash != null) {
         client.leave(fhash);
         fhash = null;
      }
	}

	/**
	 * Subclass should override this method if it is interested when programs become active.
	 * Note: this method is called in response to a ProgramActivatedPluginEvent. 
	 * 
	 * At the time this method is called, 
	 * the "currentProgram" variable will be set the new active program.
	 * 
	 * @param program the new program going active.
	 */
	protected void programActivated(Program program) {
      prog = program;
      flat = new FlatProgramAPI(prog);
      fhash = prog.getExecutableSHA256().toUpperCase();
      conf = new RevsyncConfig();
      client = new RevsyncClient(this, conf);
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program location events.
	 * @param loc location could be null
	 */
	protected void locationChanged(ProgramLocation loc) {
	   if (loc == null) {
	      return;
	   }
      if (loc instanceof EolCommentFieldLocation || loc instanceof RepeatableCommentFieldLocation) {
         CommentFieldLocation comm = (CommentFieldLocation)loc;
         String[] cmt = comm.getComment();  //coalesce into a single string
         try {
            Address ea = loc.getAddress();
            boolean changed = comments.parse_comment_update(ea, client.nick, cmt);
            TreeMap<String,Object> data = new TreeMap<String,Object>();
            data.put("cmd", "comment");
            if (changed) {
               data.put("text", text);
            }
            else {
               data.put("text", "");
            }
            data.put("addr", get_can_addr(ea));
            publish(data, false);
         } catch (Comments.NoChange nc) {
         }
      }
	   else if (loc instanceof LabelFieldLocation) {
         LabelFieldLocation label = (LabelFieldLocation)loc;
         String name = label.getName();
	   }
	   else if (loc instanceof OperandFieldLocation) {
         OperandFieldLocation op = (OperandFieldLocation)loc;
	   }
	}

}


