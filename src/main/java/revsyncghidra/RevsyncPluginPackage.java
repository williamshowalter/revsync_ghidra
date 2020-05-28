package revsyncghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.util.Msg;
import resources.ResourceManager;

// This class lets us show up in Configure Tool as a main-level category
public class RevsyncPluginPackage extends PluginPackage {
	public static final String NAME = "Revsync";
	
	public RevsyncPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/update_tango_publicdomain.png"),
				"Revsync plugin", EXAMPLES_PRIORITY);
		Msg.info(this, "RevSyncPluginPackage constructor");
	}
}
