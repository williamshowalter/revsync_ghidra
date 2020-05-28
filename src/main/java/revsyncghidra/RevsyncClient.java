package revsyncghidra;

import java.lang.reflect.Type;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.Pair;

import java.nio.*;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import ghidra.util.Msg;
import redis.clients.jedis.*;

public class RevsyncClient {

	public class RevSub extends JedisPubSub {

		protected RevSyncGhidraPlugin frontend;

		public RevSub(RevSyncGhidraPlugin frontend) {
			this.frontend = frontend;
		}

		public void onMessage(String channel, String message) {	
			if (!channel.contentEquals(key)) {
				Msg.error(this, "it really shouldn't be possible to reach here, since we only subscribe to channel key.");
				Msg.error(this, "hash mismatch, dropping message on bad channel " + channel);
				frontend.consolePrint("hash mismatch, dropping message on bad channel " + channel);
				return;
			}
			
			TreeMap<String,Object> data = decode(message);

			if (data.containsKey("user")){
				data.replace("user", ((String)data.get("user")).replace(nick_filter,"_"));
			}
			
			// reject our own messages
			if (data.get("uuid") != null && data.get("uuid").equals(uuid)) {
				return;
			}
			
			synchronized (lock) {
				nosend = remove_ttl(nosend);
				Vector<Object> tv = new Vector<Object>();
				tv.add(serverTimeSec());
				for (Object i : dtokey(data)) {
					tv.add(i);
				}
				nosend.add(tv);
			}
			frontend.revsync_callback(data, false);
		}

		public void onPMessage(String pattern, String channel, String message) {
			Msg.info(this, "got pmessage: " + message);
		}

		public void onSubscribe(String channel, int subscribedChannels) {
			Msg.info(this, "got message: onSubscribe: " + channel);

			Vector<TreeMap<String,Object>> state = new Vector<TreeMap<String,Object>>();
			Vector<TreeMap<String,Object>> decoded = new Vector<TreeMap<String,Object>>();
			List<String> previousMessages;
			synchronized (lock) {
				previousMessages =  jedisGen.lrange(key, 0, -1);
			}
			for (String m : previousMessages) {
				try {
					decoded.add(decode(m));
				} catch(Exception e) {
					Msg.error(this,  "Error decoding previous messages: " + m);
					frontend.consolePrint("Error decoding previous message: " + m);
					continue;
				}
			}

			Set<Vector<String>> dedup = new HashSet<Vector<String>>();
			Collections.reverse(decoded);
			for (TreeMap<String,Object> d : decoded) {
				String cmd = (String)d.get("cmd");
				if (cmd != null) {
					Vector<String> hashkey = new Vector<String>();
					for (String k : hash_keys) {
						Object e  = d.get(k);
						if (e != null) {
							hashkey.add((String)e);
						}
					}
					if (cmd_hash_keys.containsKey(cmd)) {
						for (String k : cmd_hash_keys.get(cmd)) {
							Object e  = d.get(k);
							if (e != null) {
								if (e instanceof String) {
									hashkey.add((String)e);
								}
								else if (e instanceof Double){
									hashkey.add(String.valueOf(e));
								}
								else {
									Msg.info(this, "Unknown type of e: " + e.getClass().toString());
								}
							}
						}
					}
					
					if (dedup.contains(hashkey)) {
						continue;
					}
					dedup.add(hashkey);
					state.add(d);
					// client.py has state.append(data) outside of if(cmd), but i dont see why we process anything
					// without a cmd??? even join is a cmd?
					// looks like ida_frontend would throw an error and catch it, binja would not catch and throw
				}
			}
			
			Collections.reverse(state);
			for (TreeMap<String,Object> d : state) {
				synchronized(lock) {
					Vector<Object> tv = new Vector<Object>();
					tv.add(serverTimeSec());
					for (Object i : dtokey(d)) {
						tv.add(i);
					}
					nosend.add(tv);
				}
				frontend.revsync_callback(d, true);
			}
		}

		public void onUnsubscribe(String channel, int subscribedChannels) {
			Msg.info(this, "Unsubscribed from channel: " + channel);
			frontend.consolePrint("Unsubscribed from channel: " + channel);
		}

		public void onPUnsubscribe(String pattern, int subscribedChannels) {
			Msg.info(this, "Pattern Unsubscribed: " + pattern);
		}

		public void onPSubscribe(String pattern, int subscribedChannels) {
			Msg.info(this, "Pattern Subscribe: " + pattern);
		}
	}

	protected class SubThread extends Thread {
		public void run() {
			jedisSub.subscribe(revsub, key);
		}
	}

	protected static final long TTL = 2000; // milliseconds - python uses seconds as doubles/float
	protected static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	protected static final HashSet<String> skip = new HashSet<String>();
	protected static final String hash_keys[] = { "cmd", "user" }; // all cmds have cmd and user
	protected static final HashMap<String, Vector<String>> cmd_hash_keys = new HashMap<String, Vector<String>>();
	protected static final HashMap<String, String> key_dec = new HashMap<String, String>();
	protected static final HashMap<String, String> key_enc = new HashMap<String, String>();
	protected static final String nick_filter = "[^a-zA-Z0-9_\\-]";

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

	protected static TreeMap<String, Object> decode(String json) {
		TreeMap<String, Object> decoded = new TreeMap<String, Object>();
		for (Entry<String, Object> e : fromJson(json).entrySet()) {
			if(key_dec.get(e.getKey())== null) {
				decoded.put(e.getKey(), e.getValue());
			}
			else {
				decoded.put(key_dec.get(e.getKey()), e.getValue());
			}
		}
		return decoded;
	}

	// treemaps are sorted, so vector should end up being?
	// python d = {'cmd': 'comment', 'addr': 984, 'text': 'newComment'}
	// python res = (('addr', 984), ('cmd', 'comment'), ('text', 'newComment'))
	protected static Vector<Pair<String, Object>> dtokey(TreeMap<String, Object> d) {
		Vector<Pair<String, Object>> res = new Vector<Pair<String, Object>>();
		for (Entry<String, Object> e : d.entrySet()) {
			if (skip.contains(e.getKey())) {
				continue;
			}
			res.add(Pair.of(e.getKey(), e.getValue()));
		}
		return res;
	}

	protected static TreeMap<String, Object> fromJson(String json) {
		Type type = new TypeToken<TreeMap<String, Object>>() {}.getType();
		return gson.fromJson(json, type);
	}

	protected Jedis jedisSub;
	protected Jedis jedisGen;
	protected String uuid;
	protected String nick;
	protected String key;
	protected RevSub revsub;
	protected SubThread subThread;
	protected Vector<Vector<Object>> nosend = new Vector<Vector<Object>>();
	final protected Object lock = new Object();

	public long serverTime() {
		List<String> ll;
		synchronized (lock) {
			ll = jedisGen.time();
		}
		return (Long.parseLong(ll.get(0)) * 1000) + (Long.parseLong(ll.get(1)) / 1000);
	}

	public long serverTimeSec() {
		List<String> ll;
		synchronized (lock) {
			ll = jedisGen.time();
		}
		return Long.parseLong(ll.get(0));
	}

	protected Vector<Vector<Object>> remove_ttl(Vector<Vector<Object>> a) {
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

	@SuppressWarnings("deprecation")
	public RevsyncClient(RevSyncGhidraPlugin frontend, RevsyncConfig conf) {
		jedisGen = new Jedis(conf.host, conf.port, 5);
		if (conf.password != null) {
			jedisGen.auth(conf.password);
		}
		jedisSub = new Jedis(conf.host, conf.port, 5);
		if (conf.password != null) {
			jedisSub.auth(conf.password);
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
	// list of tuples in python,
	// where each tuple was a Double time, followed by arbitrary number of
	// key:value tuples.
	/*
	 * debounce no = [ (1590287867.9123807, ('addr', 888), ('cmd', 'comment'),
	 * ('text', ';jj')), (1590287869.1665049, ('addr', 892), ('cmd', 'comment'),
	 * ('text', 'j;j')) ] data = {'cmd': 'comment', 'addr': 984, 'text':
	 * 'newComment'} <-- this is from other end
	 * 
	 * dtokey = (('addr', 984), ('cmd', 'comment'), ('text', 'newComment'))
	 * 
	 */
	protected Boolean debounce(Vector<Vector<Object>> no, TreeMap<String, Object> data) {
		Vector<Pair<String, Object>> dkey = dtokey(data);
		long now = serverTime();
		synchronized (lock) {
//			Msg.info(this, "No: " + no.toString() + "\n" + "data: " + data.toString());
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
		key = subKey;
		subThread = new SubThread();
		subThread.start();

		TreeMap<String, Object> data = new TreeMap<String, Object>();
		data.put("cmd", "join");
		publish(data, false, true);
	}

	// need to test to make sure we can't trigger events after leave happens - since
	// key is null etc.
	public void leave() {
		revsub.unsubscribe(key);
		key = null;
	}

	public void publish(TreeMap<String, Object> data, boolean perm, boolean send_uuid) {
		if (debounce(nosend, data)) {
			return;
		}

		data.put("user", nick);
		data.put("ts", serverTimeSec());
		if (send_uuid) {
			data.put("uuid", uuid);
		}
		
		TreeMap<String, Object> encoded = new TreeMap<String, Object>();
		for (Entry<String, Object> e : data.entrySet()) {
			if(key_enc.get(e.getKey()) == null) {
				// Not in key_enc, such as ts
				encoded.put(e.getKey(), e.getValue());
			}
			else {
				encoded.put(key_enc.get(e.getKey()), e.getValue());
			}
		}
		
		String json = gson.toJson(encoded);
		if (perm) {
			synchronized (lock) {
				jedisGen.rpush(key, json);
			}
		}
		synchronized (lock) {
			jedisGen.publish(key, json);
		}
	}

	public void publish(TreeMap<String, Object> data, boolean send_uuid) {
		publish(data, true, send_uuid);
	}

	public void publish(TreeMap<String, Object> data) {
		publish(data, true, true);
	}

	public void push(TreeMap<String, Object> data, boolean send_uuid) {
		if (send_uuid) {
			data.put("uuid", uuid);
		}
		synchronized (lock) {
			jedisGen.lpush(key, gson.toJson(data));
		}
	}

	public void push(TreeMap<String, Object> data) {
		push(data, true);
	}

}
