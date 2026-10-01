package com.velocity.jwakfu.testclient;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Minimal Wakfu client used to exercise the server without the real game client:
 * version handshake, RSA login, world list and character list.
 *
 * Usage: java -cp jWakfu-0.1.0-all.jar com.velocity.jwakfu.testclient.TestClient [host] [port] [user] [password]
 */
public class TestClient {

	private static final long RSA_VERIFICATION_LONG = 0x8000000000000000L;
	private static final int WORLD_ID = 1606;

	private final DataInputStream in;
	private final DataOutputStream out;

	public TestClient(Socket socket) throws IOException {
		socket.setSoTimeout(3000);
		in = new DataInputStream(socket.getInputStream());
		out = new DataOutputStream(socket.getOutputStream());
	}

	public static void main(String[] args) throws Exception {
		String host = args.length > 0 ? args[0] : "127.0.0.1";
		int port = args.length > 1 ? Integer.parseInt(args[1]) : 5558;
		String user = args.length > 2 ? args[2] : "velocity";
		String pass = args.length > 3 ? args[3] : "cheese";

		try (Socket socket = new Socket(host, port)) {
			new TestClient(socket).run(user, pass);
		}
	}

	private void run(String user, String pass) throws Exception {
		step("Version handshake (packet 7)");
		ByteArrayOutputStream p = new ByteArrayOutputStream();
		DataOutputStream d = new DataOutputStream(p);
		d.writeByte(1);
		d.writeShort(50);
		d.writeByte(2);
		writeString(d, "90414");
		send(7, p.toByteArray());

		byte[] versionAck = expect(8, "version ack");
		byte[] rsaKey = expect(1034, "RSA key");
		check(versionAck.length > 0 && versionAck[0] == 1, "version accepted");
		DataInputStream k = new DataInputStream(new java.io.ByteArrayInputStream(rsaKey));
		check(k.readLong() == RSA_VERIFICATION_LONG, "RSA verification long matches");
		byte[] pub = new byte[rsaKey.length - 8];
		k.readFully(pub);

		step("Login (packet 1026) as " + user);
		PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		ByteArrayOutputStream plain = new ByteArrayOutputStream();
		DataOutputStream pd = new DataOutputStream(plain);
		pd.writeLong(RSA_VERIFICATION_LONG);
		writeString(pd, user);
		writeString(pd, pass);
		byte[] enc = cipher.doFinal(plain.toByteArray());
		p = new ByteArrayOutputStream();
		d = new DataOutputStream(p);
		d.writeInt(enc.length);
		d.write(enc);
		send(1026, p.toByteArray());

		byte[] login = expect(1027, "login response");
		check(login.length > 0 && login[0] == 0, "login accepted (response code " + (login.length > 0 ? login[0] : -1) + ")");
		byte[] worlds = expect(1036, "world list");
		System.out.println("    world list: " + worlds.length + " bytes");

		step("Refresh worlds (packet 1035)");
		send(1035, new byte[0]);
		expect(1036, "world list");

		step("List characters (packet 1201) for world " + WORLD_ID);
		send(1201, new byte[] { 0, 0, (byte) (WORLD_ID >> 8), (byte) WORLD_ID });
		byte[] chars = expect(1202, "character list response");
		check(chars.length > 0 && chars[0] == 0, "character list ok");
		expect(2063, "server time");
		expect(2077, "companions");

		System.out.println("\nALL STEPS PASSED");
	}

	/** Client frames are: size(2) type(1) opcode(2) payload. */
	private void send(int opcode, byte[] payload) throws IOException {
		// The server has no frame reassembly, so each packet must go out in a single write.
		ByteArrayOutputStream frame = new ByteArrayOutputStream();
		DataOutputStream f = new DataOutputStream(frame);
		f.writeShort(payload.length + 5);
		f.writeByte(0);
		f.writeShort(opcode);
		f.write(payload);
		out.write(frame.toByteArray());
		out.flush();
		System.out.println("  -> sent opcode " + opcode + " (" + payload.length + " bytes)");
	}

	/** Server frames are: size(2, includes header) opcode(2) payload. Returns the payload. */
	private byte[] expect(int opcode, String what) throws IOException {
		int size = in.readUnsignedShort();
		int op = in.readUnsignedShort();
		byte[] payload = new byte[size - 4];
		in.readFully(payload);
		System.out.println("  <- got opcode " + op + " (" + payload.length + " bytes)");
		check(op == opcode, what + " (expected opcode " + opcode + ", got " + op + ")");
		return payload;
	}

	private static void writeString(DataOutputStream d, String s) throws IOException {
		d.writeByte(s.length());
		d.writeBytes(s);
	}

	private static void step(String s) {
		System.out.println("\n== " + s);
	}

	private static void check(boolean ok, String what) {
		System.out.println("  [" + (ok ? "OK" : "FAIL") + "] " + what);
		if (!ok) {
			System.exit(1);
		}
	}

}
