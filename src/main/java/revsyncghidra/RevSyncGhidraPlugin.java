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
	public static String[] ghidra_reserved_prefix = { "SUB_", "FUN_", "locret_", "LOC_", "off_",
	 "seg_", "asc_", "byte_", "word_", "dword_", "qword_", "byte3_", "xmmword_", "ymmword_", 
	 "packreal_", "flt_", "dbl_", "tbyte_", "stru_", "custdata_", "algn_", "unk_" };
	 
    public RevsyncConfig config;
    public RevsyncClient client;

	/**
	 * Plugin constructor.
	 * 
	 * WILL: It's important to note that the Program might not be activated/loaded 
	 * yet when this constructor is ran.
	 * Which is why Program activated initializes some data.
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
        action = new DockingAction("Load Revsync", getName() ) {
            @Override
            public void actionPerformed( ActionContext context ) {
                loadRevsync();
            }
        };
        action.setEnabled( currentProgram != null );        
        action.setMenuBarData( new MenuData( new String[]{"Revsync","Load Revsync"}, "Revsync" ) );
        tool.addAction(action);
        loadRevsyncAction = action;
        
        // Stop Revsync menu
        action = new DockingAction("Stop Revsync", getName()) {
        	@Override
        	public void actionPerformed( ActionContext context ) {
        		stopRevsync();
        	}
        };
        action.setEnabled(false);
        action.setMenuBarData( new MenuData( new String[] {"Revsync","Stop Revsync"}, "Revsync"));
        tool.addAction(action);
        stopRevsyncAction = action;
    }

	/**
	 * This is the callback method for DomainObjectChangedEvents.
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord record = ev.getChangeRecord(i);
			if (record instanceof ProgramChangeRecord) {
				ProgramChangeRecord r = (ProgramChangeRecord) record;
				consolePrint(r.toString());
			}
		}
	}
    
	// binja_frontend never uses replay, seeing if I need it or not
	public void revsync_callback(TreeMap<String,Object> data, Boolean replay) {
		// need to implement
		Msg.info(this, "data: " + data.toString() + " replay: "+ replay.toString());
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
		} catch(Exception e) {
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
		}
		else {
			console.addMessage("Revsync", message);
		}
    }
    
    protected void announce(String message) {
		consolePrint(message);
    	JOptionPane.showMessageDialog(null,message,"Revsync",
                                      JOptionPane.INFORMATION_MESSAGE);
    }
}
