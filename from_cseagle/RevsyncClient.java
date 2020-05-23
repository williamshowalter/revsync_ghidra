import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.nio.*;
import java.time.*;
import com.google.gson.*;
import redis.clients.jedis.*;

//don't know whether this needs to be a thread or not, maybe Jedis jedis 
//starts its own thread?
public class RevsyncClient {
   
   public class RevSub extends JedisPubSub {
 
      public RevsyncFrontend frontend;

      public RevSub(RevsyncFrontend frontend) {
         this.frontend = frontend;
      }

      public void onMessage(String channel, String message) {
         //got a message
         TreeMap<String,Object> map = fromJson(message);
         if (map.containsKey("user")) {
            String user = (String)map.get("user");
            map.put("user", user.replace(nick_filter, "_"));
         }
         // reject our own messages
         if (map.get("uuid").equals(uuid)) {
            return;
         }
         synchronized (lock) {
            nosend.put(channel, remove_ttl(nosend.getOrDefault(channel, new Vector<String>())));
            nosend.get(channel).add((System.currentTimeMillis() + dtokey(data)));
         }
         frontend.onmsg_safe(key, data);
      }

      public void onPMessage(String pattern, String channel, String message) {}

      public void onSubscribe(String channel, int subscribedChannels) {}
   
      public void onUnsubscribe(String channel, int subscribedChannels) {}
   
      public void onPUnsubscribe(String pattern, int subscribedChannels) {}

      public void onPSubscribe(String pattern, int subscribedChannels) {}
   }
   
   public static final long TTL = 2000;  //milliseconds

   public static Gson gson = new Gson();

   public static HashSet<String> skip = new HashSet<String>();
   public static String hash_keys[] = {"cmd", "user"};
   public static HashMap<String,Vector<String>> cmd_hash_keys = new HashMap<String,Vector<String>>();
   public static HashMap<String,String> key_dec = new HashMap<String,String>();
   public static HashMap<String,String> key_enc = new HashMap<String,String>();
   public static String nick_filter = "[^a-zA-Z0-9_\\-]";

   static {
      Vector<String> t = new Vector<String>();
      t.add("addr");
      cmd_hash_keys.put("comment", t);
      cmd_hash_keys.put("extra_comment", t);
      cmd_hash_keys.put("area_comment", t);
      cmd_hash_keys.put("rename", t);
      t = new Vector<String>();
      t.add("addr");
      t.add("offset");
      t.add("name");
      cmd_hash_keys.put("stackvar_renamed", t);
      t = new Vector<String>();
      t.add("struc_name");
      cmd_hash_keys.put("struc_deleted", t);
      t = new Vector<String>();
      t.add("struc_name");
      t.add("is_union");
      cmd_hash_keys.put("struc_created", t);
      t = new Vector<String>();
      t.add("old_name");
      t.add("new_name");
      cmd_hash_keys.put("struc_renamed", t);
      t = new Vector<String>();
      t.add("struc_name");
      t.add("offset");
      cmd_hash_keys.put("struc_member_deleted", t);
      t = new Vector<String>();
      t.add("struc_name");
      t.add("offset");
      t.add("member_name");
      cmd_hash_keys.put("struc_member_renamed", t);
      t = new Vector<String>();
      t.add("struc_name");
      t.add("offset");
      t.add("size");
      cmd_hash_keys.put("struc_member_changed", t);
      t = new Vector<String>();
      t.add("struc_name");
      t.add("offset");
      t.add("member_name");
      t.add("size");
      t.add("flag");
      cmd_hash_keys.put("struc_member_created", t);

      key_dec.put("c", "cmd");
      key_dec.put("a", "addr");
      key_dec.put("u", "user");
      key_dec.put("t", "text");
      key_dec.put("i", "uuid");
      key_dec.put("b", "blocks");

      for (String k : key_dec.keySet()) {
         key_enc.put(key_dec.get(k), k);
      }
      
      skip.add("ts");
      skip.add("uuid");
      skip.add("user");
   }

   public static TreeMap<String,Object> decode(String json) {
      TreeMap<String, Object> res = gson.fromJson(json, TreeMap.class);
//      d = json.loads(data)
//      return dict((key_dec.getOrDefault(k, k), v) for k, v in d.items())
      return res;
   }
   
   public static Vector<TreeMap<String,Object>> dtokey(TreeMap<String,Object> d) {
      Vector<TreeMap<String,Object>> res = new Vector<TreeMap<String,Object>>();
      for (String k : d.keySet()) {
         if (skip.contains(k)) {
            continue;
         }
         TreeMap<String,Object> tm = new TreeMap<String,Object>();
         tm.put(k, d.get(k));
         res.add(tm);
      }
      return res;
   }
   
   public static Vector<Vector<Object>> remove_ttl(Vector<Vector<Object>> a) {
      long now = System.currentTimeMillis();
      Vector<Vector<Object>> res = new Vector<Vector<Object>>();
      for (Vector<Object> v : a) {
         if ((now - v.get(0)) < TTL) {
            res.add(v);
         }
      }
      return res;
   }
   
   public static TreeMap<String,Object> fromJson(String json) {
      return gson.fromJson(json, TreeMap.class);
   }

   public Jedis jedis;
   public String uuid;
   public String nick;
   public Object lock;
   public HashMap<String,Object> ps = new HashMap<String,Object>();
   public RevSub revsub = new RevSub(frontend);

   public long serverTime() {
      List<String> ll = jedis.time();
      for (String s : ll) {
         System.err.println(s);
      }
      Long v0 = new Long(ll.get(0));
      long result = v0.longValue() * 1000;
      v0 = new Long(ll.get(1));
      result += v0.longValue() / 1000;
      return result;
   }

   public long serverTimeSec() {
      List<String> ll = jedis.time();
      for (String s : ll) {
         System.err.println(s);
      }
      return new Long(ll.get(0));
   }

   public RevsyncClient(RevsyncFrontend frontend, RevsyncConfig conf) { //String host, int port, String nick, String password) {
      jedis = new Jedis(conf.host, conf.port, 5);
      if (conf.password != null) {
         jedis.auth(conf.password);
      }
      UUID u = UUID.randomUUID();
      ByteBuffer bb = ByteBuffer.allocate(16);
      bb.putLong(u.getMostSignificantBits());
      bb.putLong(u.getLeastSignificantBits());
      uuid = Base64.getEncoder().encodeToString(bb.array());
      nick = conf.nick.replace(nick_filter, "_");
      revsub = new RevSub(frontend);
   }

   public String debounce(Vector<Vector<Object>> no, TreeMap<String,Object> data) {
      Vector<TreeMap<String,Object>> dkey = dtokey(data);
      long now = System.currentTimeMillis();
      synchronized (lock) {
         for (Vector<Object> d : no) {
            long ts = ((Long)d.get(0)).longValue();
            Vector<TreeMap<String,Object>> key = new Vector<TreeMap<String,Object>>();
            for (int i = 1; i < data.size(); i++) {
               key.put(data.get(i));
            }
            if (dkey.equals(key) && (now - ts) < TTL) {
               no.remove(d);
               return true;
            }
         }
      }
      return false;
   }

   public void join(String key) {
      jedis.subscribe(revsub, key);
/*
      ps.subscribe(key);
      RedisThread rt = new RedisThread(ps, cb, key);
      rt.start();

      this.ps.put(key, ps);
*/
      TreeMap<String,String> data = new TreeMap<String,String>();
      data.put("cmd", "join");
      publish(key, data, false);
   }

   public void leave(String key) {
      revsub.unsubscribe(key);
   }

   public void publish(String key, TreeMap<String,Object> data, boolean send_uuid, boolean perm) {
      if (debounce(nosend.get(key), data)) {
         return;
      }

      data.put("user", nick);
      data.put("ts", serverTimeSec());
      if (send_uuid) {
         data.put("uuid", uuid);
      }
      String json = gson.toJson(data);
      if (perm) {
         jedis.rpush(key, json);
      }
      jedis.publish(key, json);
   }

   public void publish(String key, TreeMap<String,Object> data, boolean send_uuid) {
      publish(key, data, send_uuid, true);
   }

   public void publish(String key, TreeMap<String,Object> data) {
      publish(key, data, true, true);
   }

   public void push(String key, TreeMap<String,Object> data, boolean send_uuid) {
      if (send_uuid) {
         data.put("uuid", uuid);
      }
      jedis.lpush(key, gson.toJson(data));
   }

   public void push(String key, TreeMap<String,Object> data) {
      push(key, data, true);
   }

}

