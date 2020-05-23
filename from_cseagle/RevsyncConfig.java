
import java.io.*;
import java.util.*;
import com.google.gson.*;

public class RevsyncConfig {

   public TreeMap<String,Object> config;
   public String host;
   public int port;
   public String nick;
   public String password;

   public RevsyncConfig() throws Exception {
      Gson gson = new Gson();
      Properties props = System.getProperties();

      // TODO: We can look in user.home/.config or user.home/.revsync or something
      String cwd = (String)props.get("user.dir");
      String fsep = (String)props.get("file.separator");
      
      FileReader fr = new FileReader(cwd + fsep + "config.json");
      config = gson.fromJson(fr, TreeMap.class);
      fr.close();

      host = (String)config.get("host");
      port = (new Double(config.get("port").toString())).intValue();
      nick = (String)config.get("nick");
      password = (String)config.getOrDefault("password", null);

   }

}
