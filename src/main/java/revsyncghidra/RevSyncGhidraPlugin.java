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
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.Msg;

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

	public String fhash;

//    public Comments comments;
	public static String[] ghidra_reserved_prefix = { "SUB_", "FUN_", "locret_", "LOC_", "off_", "seg_", "asc_",
			"byte_", "word_", "dword_", "qword_", "byte3_", "xmmword_", "ymmword_", "packreal_", "flt_", "dbl_",
			"tbyte_", "stru_", "custdata_", "algn_", "unk_" };

	public RevsyncConfig config;
	public RevsyncClient client;

	/**
	 * Plugin constructor.
	 * 
	 * WILL: It's important to note that the Program might not be activated/loaded
	 * yet when this constructor is ran. Which is why Program activated initializes
	 * some data.
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
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord record = ev.getChangeRecord(i);
				if (record instanceof ProgramChangeRecord) {
					ProgramChangeRecord r = (ProgramChangeRecord) record;
					consolePrint("DEBUG comment changed: " + r.toString());
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
			consolePrint("Got " + String.valueOf(ev.numRecords()) + " records");
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord record = ev.getChangeRecord(i);
				if (record instanceof ProgramChangeRecord) {
					ProgramChangeRecord r = (ProgramChangeRecord) record;
					consolePrint("DEBUG comment changed: " + r.toString());
				}
			}
		}

		// all other events
		else {
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord record = ev.getChangeRecord(i);
				if (record instanceof ProgramChangeRecord) {
					ProgramChangeRecord r = (ProgramChangeRecord) record;
					try {
						consolePrint("DEBUG domainObjectChanged: " + r.toString());
						consolePrint("Start " + r.getStart().toString());
						consolePrint("End " + r.getEnd().toString());
					} catch (Exception e) {
						consolePrint("Couldnt print event");
					}
					// object is null in some/most cases? just use address
				}
			}
		}
	}

	// binja_frontend never uses replay, seeing if I need it or not
	public void revsync_callback(TreeMap<String, Object> data, Boolean replay) {
		Msg.info(this, "data: " + data.toString() + " replay: " + replay.toString());
		String cmd = (String) data.get("cmd");
		String user = (String) data.get("user");
		Long ts = ((Double) data.get("ts")).longValue();

		if (cmd == null) {
			consolePrint("Error - no cmd in message");
			return;
		} else if (cmd.equals("comment")) {

		} else if (cmd.equals("extra_comment")) {

		} else if (cmd.equals("area_comment")) {

		} else if (cmd.equals("rename")) {

		} else if (cmd.equals("stackvar_renamed")) {

		} else if (cmd.equals("struc_created")) {

		} else if (cmd.equals("struc_deleted")) {

		} else if (cmd.equals("struc_renamed")) {

		} else if (cmd.equals("struc_member_created")) {

		} else if (cmd.equals("struc_member_deleted")) {

		} else if (cmd.equals("struc_member_renamed")) {

		} else if (cmd.equals("struc_member_changed")) {

		}
		// Done
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
		Msg.info(this, "opened");
		console = tool.getService(ConsoleService.class);
		loadRevsyncAction.setEnabled(program != null);
		fhash = program.getExecutableSHA256().toUpperCase();
	}

	/**
	 * Called when the program is closed.
	 */
	@Override
	protected void programDeactivated(Program program) {
		Msg.info(this, "closed");
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
