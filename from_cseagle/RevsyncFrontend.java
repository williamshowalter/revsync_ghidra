
import java.util.*;

public interface RevsyncFrontend {
   public void onmsg_safe(String key, TreeMap<String,Object> data, boolean replay);
   public void onmsg_safe(String key, TreeMap<String,Object> data);
}
