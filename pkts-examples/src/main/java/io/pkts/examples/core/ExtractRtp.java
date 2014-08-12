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
import io.pkts.packet.PacketFactory;
import io.pkts.packet.TransportPacketFactory;
import io.pkts.packet.UDPPacket;
import io.pkts.packet.rtp.RtpPacket;
import io.pkts.protocol.IllegalProtocolException;
import io.pkts.protocol.Protocol;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * @author jonas
 *
 */
public class ExtractRtp implements PacketHandler {

    public static final int FILTER_PAYLOAD_TYPE = 111;
    public static int count = 0;
    private final RTPFramer framer = new RTPFramer();
    private final PcapOutputStream out;
    private final TransportPacketFactory factory = PacketFactory.getInstance().getTransportFactory();

    public ExtractRtp(final PcapOutputStream out) {
        this.out = out;

    }

    @Override
    public void nextPacket(final Packet packet) throws IOException {

        if (packet.hasProtocol(Protocol.UDP)) {
            final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
            final Buffer payload = udp.getPayload();
            try {
                if (payload.getByte(0) == (byte) (0x80)) {
                    final RtpPacket rtp = this.framer.frame(udp, payload);
                    if (rtp.getPayloadType() == FILTER_PAYLOAD_TYPE) {
                        ++count;
                        final long ts = udp.getArrivalTime();
                        final UDPPacket udpPkt = this.factory.createUDP(ts / 1000, payload.clone());
                        udpPkt.setDestinationIP("10.36.10.100");
                        udpPkt.setSourcePort(1234);
                        udpPkt.setSourceIP("10.36.10.101");
                        udpPkt.setDestinationPort(6789);
                        udpPkt.setSourceMacAddress("12:13:14:15:16:17");
                        udpPkt.setDestinationMacAddress("01:02:03:04:05:06");
                        this.out.write(udpPkt);
                    }
                }

            } catch (final IllegalArgumentException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (final IllegalProtocolException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    public static void main(final String[] args) throws Exception {

        // TODO: change input file
        final String dir = "/Users/wsong/Twilio/project/current/webrtc-11-01";
        final File f = new File(dir + "/opus-large-skew-1.pcap");

        System.out.println("Only create RTP with PT=" + FILTER_PAYLOAD_TYPE);

        final Pcap stupid = Pcap.openStream("/Users/wsong/Twilio/project/current/pcmu.pcap");

        final Pcap pcap = Pcap.openStream(f);
        final PcapOutputStream out = stupid.createOutputStream(new BufferedOutputStream(new FileOutputStream(dir
                + "/fixed.pcap")));
        final ExtractRtp oneOff = new ExtractRtp(out);
        pcap.loop(oneOff);
        out.close();
        System.out.println("Total pkts created: " + count);
    }
}
