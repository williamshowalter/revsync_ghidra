package revsyncghidra;
import java.io.FileReader;
import java.util.Properties;
import java.util.TreeMap;

import com.google.gson.*;

import ghidra.app.services.ConsoleService;

public class RevsyncConfig {

   public String host;
   public int port;
   public String nick;
   public String password;

   public RevsyncConfig(ConsoleService console) throws Exception {
      TreeMap<String,Object> config;

      Gson gson = new Gson();
      Properties props = System.getProperties();

      // TODO: We can look in user.home/.config or user.home/.revsync or something
      String cwd = (String)props.get("user.dir");
      String fsep = (String)props.get("file.separator");
      String fPath = cwd+fsep + ".revsync" + fsep + "config.json";
      console.addMessage("RevsyncConfig", "Loading config from: " + fPath);
      
      FileReader fr = new FileReader(fPath);
      config = gson.fromJson(fr, TreeMap.class);
      fr.close();

      host = (String)config.get("host");
      port = Double.valueOf((config.get("port").toString())).intValue();
      nick = (String)config.get("nick");
      password = (String)config.getOrDefault("password", null);
      
   }

}
