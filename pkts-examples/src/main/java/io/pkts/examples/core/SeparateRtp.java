/**
 *
 */
package io.pkts.examples.core;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.PcapOutputStream;
import io.pkts.buffer.Buffer;
import io.pkts.framer.RTPFramer;
import io.pkts.packet.Packet;
import io.pkts.packet.UDPPacket;
import io.pkts.packet.rtp.RtpPacket;
import io.pkts.protocol.Protocol;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author jonas
 *
 */
public class SeparateRtp implements PacketHandler {

    private final RTPFramer framer = new RTPFramer();
    private final Map<Long, List<Packet>> pktStreams = new HashMap<Long, List<Packet>>();

    @Override
    public void nextPacket(final Packet packet) throws IOException {
        if (packet.hasProtocol(Protocol.UDP)) {
            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
            final Buffer payload = udp.getPayload();

            // only RTP packets
            if (payload.getByte(0) == (byte) (0x80)) {
                final RtpPacket rtp = this.framer.frame(udp, payload);
                if (rtp.getPayloadType() < 0 || rtp.getPayloadType() > 127) {
                    System.err.println("RTP payload type is not 0--127: " + rtp.getPayloadType());
                }

                final long ssrc = rtp.getSyncronizationSource();
                List<Packet> stream = this.pktStreams.get(ssrc);
                if (stream == null) {
                    stream = new ArrayList<Packet>();
                    this.pktStreams.put(ssrc, stream);
                }
                stream.add(packet);
            }
        }
    }

    public void generatePcaps(final Pcap pcap) throws Exception {
        for (final Map.Entry<Long, List<Packet>> entry : this.pktStreams.entrySet()) {
            final String fname = "0x" + Long.toHexString(entry.getKey()).toUpperCase() + ".pcap";
            final PcapOutputStream outStream = pcap.createOutputStream(new FileOutputStream(fname));
            for (final Packet pkt : entry.getValue()) {
                outStream.write(pkt);
            }
            outStream.close();
        }
    }

    public void dumpStats() throws IOException {
        printLine(this.pktStreams.size() + " streams");
        for (final Map.Entry<Long, List<Packet>> entry : this.pktStreams.entrySet()) {
            printLine(String.format("0x%X count: %d", entry.getKey(), entry.getValue().size()));
        }
    }

    public static void printLine(final String text) throws IOException {
        System.out.println(text);
    }

    public static void main(final String[] args) throws Exception {

        // TODO: default file path for testing
        String path = "/Users/wsong/Twilio/project/bug-fix/VOICE-906/pcmu.pcap";
        if (args.length >= 1) {
            path = args[0];
        }

        final Pcap pcap = Pcap.openStream(path);
        final SeparateRtp oneOff = new SeparateRtp();

        pcap.loop(oneOff);
        oneOff.dumpStats();
        oneOff.generatePcaps(pcap);
    }
}
