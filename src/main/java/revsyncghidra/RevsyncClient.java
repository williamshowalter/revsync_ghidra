package revsyncghidra;

import java.io.*;
import java.lang.reflect.Type;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.Pair;

import java.nio.*;
import java.time.*;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import ghidra.util.Msg;
import redis.clients.jedis.*;

//don't know whether this needs to be a thread or not, maybe Jedis jedis 
//starts its own thread?
public class RevsyncClient {

	public class RevSub extends JedisPubSub {

		protected RevSyncGhidraPlugin frontend;

		public RevSub(RevSyncGhidraPlugin frontend) {
			this.frontend = frontend;
		}

		public void onMessage(String channel, String message) {
			// got a message
			Msg.info(this, "got message: " + message);
//         TreeMap<String,Object> map = fromJson(message);
//         if (map.containsKey("user")) {
//            String user = (String)map.get("user");
//            map.put("user", user.replace(nick_filter, "_"));
//         }
//         // reject our own messages
//         if (map.get("uuid").equals(uuid)) {
//            return;
//         }
//         synchronized (lock) {
//            nosend.put(channel, remove_ttl(nosend.getOrDefault(channel, new Vector<String>())));
//            nosend.get(channel).add((System.currentTimeMillis() + dtokey(data)));
//         }
//         frontend.onmsg_safe(key, data);
		}

		public void onPMessage(String pattern, String channel, String message) {
			Msg.info(this, "got message: " + message);
		}

		public void onSubscribe(String channel, int subscribedChannels) {
			Msg.info(this, "got message: onSubscribe: " + channel);
		}

		public void onUnsubscribe(String channel, int subscribedChannels) {
			Msg.info(this, "got message: onUnsubscribe: " + channel);
		}

		public void onPUnsubscribe(String pattern, int subscribedChannels) {
			Msg.info(this, "got message: on PUnsubscribe: " + pattern);
		}

		public void onPSubscribe(String pattern, int subscribedChannels) {
			Msg.info(this, "got message: on PSubscribe: " + pattern);
		}
	}

	protected class SubThread extends Thread {
		public void run() {
			jedis.subscribe(revsub, key);
		}
	}

	protected static final long TTL = 2000; // milliseconds - python uses seconds and doubles
	protected static Gson gson = new Gson();
	public static HashSet<String> skip = new HashSet<String>();
	public static String hash_keys[] = { "cmd", "user" };
	public static HashMap<String, Vector<String>> cmd_hash_keys = new HashMap<String, Vector<String>>();
	public static HashMap<String, String> key_dec = new HashMap<String, String>();
	public static HashMap<String, String> key_enc = new HashMap<String, String>();
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

	public static TreeMap<String, Object> decode(String json) {
		TreeMap<String, Object> decoded = new TreeMap<String, Object>();
		for (Entry<String, Object> e : fromJson(json).entrySet()) {
			decoded.put(key_dec.get(e.getKey()), e.getValue());
		}
		Msg.info("decodeFunc", decoded.toString());
		return decoded;
	}

	// treemaps are sorted, so vector should end up being?
	// python d = {'cmd': 'comment', 'addr': 984, 'text': 'newComment'}
	// python res = (('addr', 984), ('cmd', 'comment'), ('text', 'newComment'))
	public static Vector<Pair<String, Object>> dtokey(TreeMap<String, Object> d) {
		Vector<Pair<String, Object>> res = new Vector<Pair<String, Object>>();
		for (Entry<String, Object> e : d.entrySet()) {
			if (skip.contains(e.getKey())) {
				continue;
			}
			res.add(Pair.of(e.getKey(), e.getValue()));
		}
		return res;
	}

	public static TreeMap<String, Object> fromJson(String json) {
		Type type = new TypeToken<TreeMap<String, Object>>() {}.getType();
		return gson.fromJson(json, type);
	}

	public Jedis jedis;
	public String uuid;
	public String nick;
	public Object lock;
	public String key;
	public RevSub revsub;
	protected SubThread subThread;
	protected Vector<Vector<Object>> nosend;

	public long serverTime() {
		List<String> ll = jedis.time();
		for (String s : ll) {
			Msg.info(this, s);
		}
		return (Long.parseLong(ll.get(0)) * 1000) + (Long.parseLong(ll.get(1)) / 1000);
	}

	public long serverTimeSec() {
		List<String> ll = jedis.time();
		for (String s : ll) {
			System.err.println(s);
		}
		return Long.parseLong(ll.get(0));
	}

	public Vector<Vector<Object>> remove_ttl(Vector<Vector<Object>> a) {
		long now = serverTime();
		Vector<Vector<Object>> res = new Vector<Vector<Object>>();

		for (Vector<Object> v : a) {
			long ts_ms = Long.parseLong(v.get(0).toString()) * 1000; // ts stored in seconds, use now in milliseconds
			if ((now - ts_ms) < TTL) {
				res.add(v);
			}
		}
		return res;
	}

	public RevsyncClient(RevSyncGhidraPlugin frontend, RevsyncConfig conf) { // String host, int port, String nick,
																				// String password) {
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
		Msg.info(this, "Revsync Client started: uuid: " + uuid + "nick: " + nick);
	}

	// okay, so changes made by the other side could trigger change events when we
	// commit them
	// (although not in binja?) so we put these in "nosend" so they no-send...
	// self.nosend[key] only makes sense in some of the python plugins perhaps, not
	// in Ghidra where
	// the plugin has a new instance each program, so we just need a nosend
	// treemap/hashmap??

	// in code here it's a vector of vector<object>, which - i guess is okay , was a
	// list of touples in python,
	// where each touple was a Double time, followed by arbitrary number of
	// key:value touples.
	/*
	 * debounce no = [ (1590287867.9123807, ('addr', 888), ('cmd', 'comment'),
	 * ('text', ';jj')), (1590287869.1665049, ('addr', 892), ('cmd', 'comment'),
	 * ('text', 'j;j')) ] data = {'cmd': 'comment', 'addr': 984, 'text':
	 * 'newComment'} <-- this is from other end
	 * 
	 * dtokey = (('addr', 984), ('cmd', 'comment'), ('text', 'newComment'))
	 * 
	 */
	public Boolean debounce(Vector<Vector<Object>> no, TreeMap<String, Object> data) {
		Vector<Pair<String, Object>> dkey = dtokey(data);
		long now = serverTime();
		synchronized (lock) {
			for (Vector<Object> d : no) {
				long ts_ms = ((Long) d.get(0)).longValue() * 1000; // to milliseconds
				Vector<Pair<String, Object>> entry = new Vector<Pair<String, Object>>();
				for (int i = 1; i < d.size(); i++) {
					entry.add((Pair<String, Object>) d.get(i));
				}
				if (dkey.equals(entry) && (now - ts_ms) < TTL) {
					no.remove(d);
					return true;
				}
			}
		}
		return false;
	}

	public void join(String subKey) {
		Msg.info(this, "subscribing");
		key = subKey;
		subThread = new SubThread();
		subThread.start();

		TreeMap<String, Object> data = new TreeMap<String, Object>();
		data.put("cmd", "join");
		Msg.info(this, "finishing subscribing");
		publish(data, false);
	}

	// need to test to make sure we can't trigger events after leave happens - since
	// key is null etc.
	public void leave() {
		Msg.info(this, "unsubscribing");
		revsub.unsubscribe(key);
		key = null;
		Msg.info(this, "finished unsubscribing");
	}

	public void publish(TreeMap<String, Object> data, boolean send_uuid, boolean perm) {
		if (debounce(nosend, data)) {
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

	public void publish(TreeMap<String, Object> data, boolean send_uuid) {
		publish(data, send_uuid, true);
	}

	public void publish(TreeMap<String, Object> data) {
		publish(data, true, true);
	}

	public void push(TreeMap<String, Object> data, boolean send_uuid) {
		if (send_uuid) {
			data.put("uuid", uuid);
		}
		jedis.lpush(key, gson.toJson(data));
	}

	public void push(TreeMap<String, Object> data) {
		push(data, true);
	}

}
