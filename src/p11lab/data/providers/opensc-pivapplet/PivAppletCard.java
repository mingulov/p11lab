// SPDX-License-Identifier: Apache-2.0
// P11Lab-authored VSmartCard launcher for the opensc-pivapplet provider.
//
// Adapted from the P11Lab-authored IsoAppletCard.java of the sibling
// opensc-isoapplet provider (same clean-room jcardsim registration-gap
// workaround: no reference-workspace text is reused here either; only the
// class name and usage strings changed, the install-via-reflection logic
// is identical). Problem: the jcardsim Simulator constructor only
// loadApplet()s cfg-registered applets (registers the class) without
// installApplet() (which invokes the applet install() + register(),
// making it selectable), so a SELECT by AID fails. Fix: construct
// VSmartCard first (which builds its Simulator with no applet properties
// set), then install exactly one applet via reflection on the
// package-private Simulator field.
//
// All inputs arrive on argv (fixed by the supervisor; nothing secret):
//   PivAppletCard <host> <port> <atr-hex> <aid-hex> <applet-class>
// The JVM exits nonzero when vpcd is unreachable, the applet cannot be
// installed, or any input is malformed. On success it blocks forever;
// the non-daemon IO thread keeps the card serving (the reloader thread
// is disabled below, so it cannot keep anything alive).
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.remote.VSmartCard;
import javacard.framework.AID;
import java.lang.reflect.Field;

public class PivAppletCard {
    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            System.err.println("usage: PivAppletCard <host> <port> <atr-hex> <aid-hex> <applet-class>");
            System.exit(2);
        }
        String host = args[0];
        int port = parsePort(args[1]);
        byte[] atr = parseHex(args[2], "atr");
        byte[] aidBytes = parseHex(args[3], "aid");
        if (aidBytes.length < 5 || aidBytes.length > 16) {
            System.err.println("PivAppletCard: aid length out of range (5-16 bytes)");
            System.exit(2);
        }
        if (!args[4].matches("[A-Za-z_][A-Za-z0-9_.]*")) {
            System.err.println("PivAppletCard: malformed applet class name");
            System.exit(2);
        }
        if (host.isEmpty() || host.length() > 255) {
            System.err.println("PivAppletCard: malformed host");
            System.exit(2);
        }
        System.setProperty("com.licel.jcardsim.vsmartcard.host", host);
        System.setProperty("com.licel.jcardsim.vsmartcard.port", Integer.toString(port));
        System.setProperty("com.licel.jcardsim.card.ATR", args[2]);
        // The frozen VSmartCard unconditionally starts its reloader
        // thread, whose listener binds all interfaces: on the proxy
        // bridge any peer could tear down the card and re-run
        // VSmartCard.main with attacker-controlled config ("isolated
        // netns is loopback-only" does not hold there). The jar is
        // sealed, so the reloader is disabled here instead: a
        // non-numeric port makes the thread die at Integer.parseInt
        // before any socket exists (the NumberFormatException trace in
        // emulator.log is the death marker), while the IO thread keeps
        // the card serving (proven by the native census).
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.port", "disabled");
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.delay", "1000");

        // Connects to vpcd (single attempt, no retry) and starts the
        // IO/reloader threads. Throws when vpcd is not listening.
        VSmartCard card = new VSmartCard(host, port);

        // The Simulator field is package-private; the jar is not modular
        // so this access is stable on the frozen JDK (verified natively).
        Field simField = VSmartCard.class.getDeclaredField("sim");
        simField.setAccessible(true);
        Simulator sim = (Simulator) simField.get(card);

        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);
        sim.installApplet(aid, args[4], new byte[0], (short) 0, (byte) 0);
        System.out.println("PivAppletCard: installed " + args[4] + " AID=" + args[3]);
        System.out.println("PivAppletCard: card ready atr=" + args[2].toUpperCase());
        // Block forever; the IO thread keeps the JVM alive.
        Thread.currentThread().join();
    }

    private static int parsePort(String text) {
        try {
            int port = Integer.parseInt(text);
            if (port >= 1 && port <= 65535) {
                return port;
            }
        } catch (NumberFormatException bad) {
            // Fall through to the usage error below.
        }
        System.err.println("PivAppletCard: malformed port");
        System.exit(2);
        return -1;
    }

    private static byte[] parseHex(String text, String what) {
        if (text.isEmpty() || text.length() > 256 || (text.length() & 1) != 0) {
            System.err.println("PivAppletCard: malformed " + what + " hex");
            System.exit(2);
        }
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < text.length(); i += 2) {
            int hi = Character.digit(text.charAt(i), 16);
            int lo = Character.digit(text.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                System.err.println("PivAppletCard: malformed " + what + " hex");
                System.exit(2);
            }
            out[i / 2] = (byte) ((hi << 4) + lo);
        }
        return out;
    }
}
