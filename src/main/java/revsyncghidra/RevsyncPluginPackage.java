package revsyncghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.util.Msg;
import resources.ResourceManager;

// This class lets us show up in Configure Tool as a main-level category
public class RevsyncPluginPackage extends PluginPackage {
	public static final String NAME = "revsync";
	
	public RevsyncPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/tango_publicdomain_update.png"),
				"Revsync Plugin Package Class", EXAMPLES_PRIORITY);
		Msg.info(this, "RevSyncPluginPackage constructor");
	}
}
