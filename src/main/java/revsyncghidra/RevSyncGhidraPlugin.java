/* ###
ADD REVSYNC LICENSE AND COPYRIGHT STUFF HERE

*/
package revsyncghidra;

import java.util.TreeMap;

import javax.swing.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.Transaction;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import revsyncghidra.Comments.NoChange;

//@formatter:off
@PluginInfo(
	// status must be released to show up in Configure menu without digging
	status = PluginStatus.RELEASED,
	packageName = RevsyncPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Revsync Plugin for Ghidra",
	description = "Revsync Plugin for Ghidra. Syncs markup to Redis in realtime.",
	servicesRequired = { ProgramManager.class /* list of service classes that this plugin requires */ },
	servicesProvided = { /* list of service classes that this plugin registers with Plugin.registerServiceProvided() */ },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)

//@formatter:on
public class RevSyncGhidraPlugin extends ProgramPlugin implements DomainObjectListener {
	private DockingAction loadRevsyncAction;
	private DockingAction stopRevsyncAction;
	private ConsoleService console;
	protected Listing listing;
	
	public RevsyncConfig config;
	public RevsyncClient client;
	private Comments comments;
	private int transactionID;
	private Object lock = new Object();

	public String fhash;

	public static String[] ghidra_reserved_prefix = { "SUB_", "FUN_", "locret_", "LOC_", "off_", "seg_", "asc_",
			"byte_", "word_", "dword_", "qword_", "byte3_", "xmmword_", "ymmword_", "packreal_", "flt_", "dbl_",
			"tbyte_", "stru_", "custdata_", "algn_", "unk_" };

	public long get_can_addr(Address addr) {
		//"""Convert an Effective Address to a canonical address."""
		return addr.getOffset() - currentProgram.getImageBase().getOffset();
	}

	public long get_ea(Long addr) {
		//"""Get Effective Address from a canonical address."""
		return addr + currentProgram.getImageBase().getOffset();
	}
	
	/**
	 * Plugin constructor.
	 * 
	 * program might not be activated/loaded yet when this constructor is ran. 
	 * Which is why programActivated initializes some data.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public RevSyncGhidraPlugin(PluginTool tool) {
		super(tool, true, true);
		setupActions();
	}

	@Override
	public void init() {
		super.init();
		// TODO: Acquire services if necessary
	}

	private void setupActions() {
		DockingAction action;

		// Load Revsync menu
		action = new DockingAction("Load Revsync", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				loadRevsync();
			}
		};
		action.setEnabled(currentProgram != null);
		action.setMenuBarData(new MenuData(new String[] { "Revsync", "Load Revsync" }, "Revsync"));
		tool.addAction(action);
		loadRevsyncAction = action;

		// Stop Revsync menu
		action = new DockingAction("Stop Revsync", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				stopRevsync();
			}
		};
		action.setEnabled(false);
		action.setMenuBarData(new MenuData(new String[] { "Revsync", "Stop Revsync" }, "Revsync"));
		tool.addAction(action);
		stopRevsyncAction = action;
	}

	/**
	 * This is the callback method for DomainObjectChangedEvents.
	 * Any changed item in the program should trigger a callback here
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// Comment updated
		if (ev.containsEvent(ChangeManager.DOCR_PRE_COMMENT_CHANGED)
				|| ev.containsEvent(ChangeManager.DOCR_POST_COMMENT_CHANGED)
				|| ev.containsEvent(ChangeManager.DOCR_EOL_COMMENT_CHANGED)
				|| ev.containsEvent(ChangeManager.DOCR_PLATE_COMMENT_CHANGED)
				|| ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED)
				|| ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED)
				|| ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED)
				|| ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED)
				|| ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED)
				|| ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED)) {
//			consolePrint("Got " + String.valueOf(ev.numRecords()) + " records"); 
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord record = ev.getChangeRecord(i);
				if (record instanceof ProgramChangeRecord) {
					ProgramChangeRecord r = (ProgramChangeRecord) record;
					// ignoring all comments except default EOL comments right now
					
					if (r.getEventType() == ChangeManager.DOCR_EOL_COMMENT_CHANGED) {				
						Address ea = r.getStart();
						String userText = (String)r.getNewValue();
						if (userText == null || (userText != null && userText.isBlank())) {
							userText = "";
						}
						try {
							userText = comments.parse_comment_update(ea, client.nick, userText);
						}
						catch (NoChange e) {
							continue;
						}
						String fullCmtText = comments.set(ea, client.nick, userText, client.serverTimeSec());
						synchronized(lock) {
							startTransaction();
							listing.setComment(ea, CodeUnit.EOL_COMMENT, fullCmtText);
							endTransaction(true);
						}
						
						TreeMap<String,Object> data = new TreeMap<String,Object>();
						Long can_addr = get_can_addr(ea);
						data.put("cmd", "comment");
						data.put("addr", can_addr);
						data.put("text", userText);
						client.publish(data);
					}
					
//					consolePrint("DEBUG comment changed: " + r.toString());
//					consolePrint("DEBUG commentAddress = " + r.getStart().toString());
//					consolePrint("DEBUG commentAddressType = " + r.getStart().getClass());
//					if (r.getObject() != null){
//						consolePrint("DEBUG commentChangeObjectClass = " + r.getObject().getClass());
//						consolePrint("DEBUG commentChangedObject = " + r.getObject().toString());
//					}
				}
			}
		}

		/*
		 * DOCR_SYMBOL_ADDED = 40; DOCR_SYMBOL_REMOVED = 41; DOCR_SYMBOL_SOURCE_CHANGED
		 * = 42; DOCR_SYMBOL_ANCHORED_FLAG_CHANGED = 43; DOCR_SYMBOL_COMMENT_CHANGED =
		 * 44; DOCR_SYMBOL_SET_AS_PRIMARY = 45; // accompanied by 41, etc
		 * DOCR_SYMBOL_RENAMED = 46; DOCR_EXTERNAL_ENTRY_POINT_ADDED = 47;
		 * DOCR_EXTERNAL_ENTRY_POINT_REMOVED = 48; DOCR_SYMBOL_SCOPE_CHANGED = 49;
		 * DOCR_SYMBOL_ASSOCIATION_ADDED = 50; DOCR_SYMBOL_ASSOCIATION_REMOVED = 51;
		 * DOCR_SYMBOL_DATA_CHANGED = 52; DOCR_SYMBOL_ADDRESS_CHANGED = 53; -- happens
		 * alongside a 40 or 46
		 * 
		 */
		// symbol renamed, need to sort if it's variable, code, or data
		else if (ev.containsEvent(ChangeManager.DOCR_SYMBOL_ADDED)
				|| ev.containsEvent(ChangeManager.DOCR_SYMBOL_REMOVED)
				|| ev.containsEvent(ChangeManager.DOCR_SYMBOL_RENAMED)) {
			// sometimes a new name will be a delete event + new name event, last record seems to always be the one we want
			DomainObjectChangeRecord record = ev.getChangeRecord(ev.numRecords()-1); // last record
			if (record instanceof ProgramChangeRecord) {
				ProgramChangeRecord r = (ProgramChangeRecord) record;
//				consolePrint("DEBUG symbol changed: " + r.toString());
//				consolePrint("DEBUG symbolAddress = " + r.getStart().toString());
//				consolePrint("DEBUG symbolAddressType = " + r.getStart().getClass());
//				if (r.getObject() != null){
//					consolePrint("DEBUG symbolChangeObjectClass = " + r.getObject().getClass());
//					consolePrint("DEBUG symbolChangedObject = " + r.getObject().toString());
//				}

				Object changedObject = r.getObject();
				if (changedObject != null && changedObject.getClass() == ghidra.program.database.symbol.VariableSymbolDB.class) {
					// function variable - not just a renamed label
				}
				// NOTE there are definitely going to be some edge cases this completely misses.
				// But it seems to work fine on generic rename of data/function/code addresses, most of
				// the delete operations too, but if something like creating/deleting functions completely
				// caused the last event in a multi-event event to not be symbol related then it could miss things.
				else {
					// Assume it's a 'rename' (generic symbol attached to EA - code/function/data
					TreeMap<String,Object> data = new TreeMap<String,Object>();
					Long can_addr = get_can_addr(r.getStart());
					String newName = r.getNewValue().toString();
					data.put("cmd", "rename");
					data.put("addr", can_addr);
					data.put("text", newName);
					client.publish(data);
				}
			}
		}

//		// all other events
//		else {
//			for (int i = 0; i < ev.numRecords(); i++) {
//				DomainObjectChangeRecord record = ev.getChangeRecord(i);
//				if (record instanceof ProgramChangeRecord) {
//					ProgramChangeRecord r = (ProgramChangeRecord) record;
//					try {
//						consolePrint("DEBUG domainObjectChanged: " + r.toString());
//						consolePrint("Start " + r.getStart().toString());
//						consolePrint("End " + r.getEnd().toString());
//					} catch (Exception e) {
//						consolePrint("Couldnt print event");
//					}
//					// object is null in some/most cases? just use address
//				}
//			}
//		}
	}
	
	private void startTransaction() {
		currentProgram.removeListener(this); // temporarily stop hooking changes
		transactionID = currentProgram.startTransaction(getClass().getName());
	}
	
	private void endTransaction(Boolean commit) {
		if (transactionID != -1) {
			currentProgram.endTransaction(transactionID, commit);
			transactionID = -1;
		}
		currentProgram.addListener(this); // resume hooking changes
	}

	private void updateSymbol(Address ea, String text) {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Symbol sym = symbolTable.getPrimarySymbol(ea);
		synchronized(lock) {
			startTransaction();
			try {
				if (sym == null) {
					if (text == null || (text != null && text.isBlank())) {
						endTransaction(false);
						return; // no symbol defined there currently, no symbol provided to set
					}
					sym = symbolTable.createLabel(ea, text, SourceType.USER_DEFINED);
					if (!sym.isPrimary()) {
						sym.setPrimary();
					}
				}
				else {
					if (text != null && !text.isBlank()) {
						sym.setName(text, SourceType.DEFAULT);						
					}
				}
				endTransaction(true);
			}
			catch (InvalidInputException e) {
				Msg.info(this, "Error setting new symbol: " + text + " at ea: " + ea.toString());
				endTransaction(false);
			}
			catch (DuplicateNameException e) {
				Msg.info(this, "Error setting new symbol: " + text + " at ea: " + ea.toString());
				endTransaction(false);
			}
		}
	}

	// binja_frontend never uses replay variable, Ghidra not using it for anything yet either
	public void revsync_callback(TreeMap<String, Object> data, Boolean replay) {
//		Msg.info(this, "data: " + data.toString() + " replay: " + replay.toString());
		String cmd = (String) data.get("cmd");
		String user = (String) data.get("user");
		Long ts = ((Double) data.get("ts")).longValue();

		if (cmd == null) {
			consolePrint("Error - no cmd in message");
			return;
		} else if (cmd.equals("comment")) {
			Long addr = get_ea(((Double) data.get("addr")).longValue());
			Address ea = currentProgram.getImageBase().getNewAddress(addr);
			consolePrint("<"+user+"> " + cmd + " " + ea.toString() + " " + (String)data.get("text"));
			String text = comments.set(ea, user, (String)data.get("text"), ts);
			synchronized(lock) {
				startTransaction();
				listing.setComment(ea, CodeUnit.EOL_COMMENT, text); // EOL is "default" comment
				endTransaction(true);
			}
		} else if (cmd.equals("extra_comment")) {
				// find out which these are closest too in PRE, POST, REPEAT, and PLATE
			Long addr = get_ea(((Double) data.get("addr")).longValue());
			Address ea = currentProgram.getImageBase().getNewAddress(addr);
			consolePrint("<"+user+"> " + cmd + " " + ea.toString() + " " + (String)data.get("text"));
		} 
		// TODO STUBBED LOG STATEMENTS - NOT EVEN SUPER HELPFUL LOGS 
		else if (cmd.equals("area_comment")) {
			// find out which these are closest too in PRE, POST, REPEAT, and PLATE
			Long addr = get_ea(((Double) data.get("addr")).longValue());
			Address ea = currentProgram.getImageBase().getNewAddress(addr);
			consolePrint("<"+user+"> " + cmd + " " + ea.toString() + " " + (String)data.get("text"));
		} else if (cmd.equals("rename")) {
			Long addr = get_ea(((Double) data.get("addr")).longValue());
			Address ea = currentProgram.getImageBase().getNewAddress(addr);
			String text = (String)data.get("text");
			consolePrint("<"+user+"> " + cmd + " " + ea.toString() + " " + text);
			updateSymbol(ea, text);
		} else if (cmd.equals("stackvar_renamed")) {
			consolePrint("<"+user+"> " + cmd + " " + (String)data.get("name"));
		} else if (cmd.equals("struc_created")) {
			consolePrint("<"+user+"> " + cmd + " " + (String)data.get("struc_name"));
		} else if (cmd.equals("struc_deleted")) {
			consolePrint("<"+user+"> " + cmd + " " +(String)data.get("struc_name"));
		} else if (cmd.equals("struc_renamed")) {
			consolePrint("<"+user+"> " + cmd + " " + (String)data.get("new_name"));
		} else if (cmd.equals("struc_member_created")) {
			consolePrint("<"+user+"> " + cmd + " " + (String)data.get("struc_name"));
		} else if (cmd.equals("struc_member_deleted")) {
			consolePrint("<"+user+"> " + cmd + " " + (String)data.get("struc_name"));
		} else if (cmd.equals("struc_member_renamed")) {
			consolePrint("<"+user+"> " + cmd + " " + (String)data.get("struc_name"));
		} else if (cmd.equals("struc_member_changed")) {
			consolePrint("<"+user+"> " + cmd + " " + (String)data.get("struc_name"));
		}
		else if (cmd.equals("join")) {
			consolePrint(user + " joined");
		} else if (cmd.equals("coverage")) {

		} else {
			consolePrint("Unknown cmd: " + cmd);
		}
		return;
	}

	/**
	 * Called when the program is opened.
	 */
	@Override
	protected void programActivated(Program program) {
		console = tool.getService(ConsoleService.class);
		listing = currentProgram.getListing();
		loadRevsyncAction.setEnabled(program != null);
		fhash = program.getExecutableSHA256().toUpperCase();
	}

	/**
	 * Called when the program is closed.
	 */
	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}

	/**
	 * Callback for menu option
	 */
	protected void loadRevsync() {
		if (currentProgram == null) {
			return;
		}

		try {
			config = new RevsyncConfig(console);
		} catch (Exception e) {
			consolePrint("Could not load config: " + e.getMessage());
			return;
		}
		
		comments = new Comments(this);

		if (client == null) {
			client = new RevsyncClient(this, config);
		}
		client.join(fhash);

		currentProgram.addListener(this);
		stopRevsyncAction.setEnabled(true);
		loadRevsyncAction.setEnabled(false); // already running

		consolePrint("Loaded with SHA256: " + fhash);
		announce("Revsync loaded for " + currentProgram.getName());
	}

	protected void stopRevsync() {
		client.leave();
		if (currentProgram == null) {
			return;
		}

		currentProgram.removeListener(this);
		stopRevsyncAction.setEnabled(false);
		loadRevsyncAction.setEnabled(true);

		announce("Revsync stopped for " + currentProgram.getName());
	}

	protected void consolePrint(String message) {
		if (console == null) {
			Msg.info(this, "Console == null; " + message);
		} else {
			console.addMessage("Revsync", message);
		}
	}

	protected void announce(String message) {
		consolePrint(message);
		JOptionPane.showMessageDialog(null, message, "Revsync", JOptionPane.INFORMATION_MESSAGE);
	}
}
