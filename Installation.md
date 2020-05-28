# Installing Revsync

![Install Extension](/install_guide/install_extensions.png)
In the Project window select File -> Install Extensions...

![Add Plugin](/install_guide/add_plugin.png)
Click the + icon in the top right to find the release .zip file.

![Select Zip](/install_guide/select_extension.png)
Choose the .zip file you downloaded and press OK.

![Please Restart](/install_guide/please_restart.png)
Acknowledge and then close and reopen Ghidra.

## ** Revsync should now be installed **

# Activating the Revsync plugin

## Automatic detection

![new extension_detected](/install_guide/new_extension_detected.png)
When you first open a program after installing Revsync, you should be presented with a notice that a new plugin was detected, and to configure it. Select yes.

If you don't see this, skip ahead to the manual method.

![enable extension](/install_guide/enable_extension.png)

Check the box for RevSyncGhidraPlugin, and then a RevSync menu should appear in the menubar. Press OK to close.

## Manually enable Revsync

Go to File -> Configure

![configure_revsync](/install_guide/file_configure_revsync.png)

Check the box for Revsync in the Configure options. NOTE: this is File->Configure in the Program window, not in the Projects window. You must be in a CodeBrowser Window.

# Create config.json file

Copy the config.json.template file to ~/.revsync/config.json

Fill out the information to point it at your redis server and set your nick - syncing won't work right for comments if nick's are not unique!

An example way to start a redis server for revsync through docker:

    docker run --rm --name redis-test -p 6379:6379 -d redis redis-server --requirepass examplePass

# Load Revsync

![load_revsync](/install_guide/load_revsync.png)

Use the Revsync menu to select Load Revsync

![loaded](/install_guide/loaded.png)

If your config.json is able to be found and the redis server is reachable, it should connect and print a loaded message, along with download all the revsync history for this executable.