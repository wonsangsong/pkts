/**
 *
 */
package io.pkts.examples.core;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.framer.RTPFramer;
import io.pkts.packet.Packet;
import io.pkts.packet.UDPPacket;
import io.pkts.packet.rtp.RtpPacket;
import io.pkts.packet.sip.SipPacket;
import io.pkts.packet.sip.header.FromHeader;
import io.pkts.protocol.Protocol;

import java.io.File;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author jonas
 *
 */
public class BulkPcapStat implements PacketHandler {

    private final static String SIP_HEADER_ORG_CALL_ID = "X-Orig-Call-ID";
    private final static String SIP_HEADER_CALL_SID = "X-Twilio-CallSid";

    private final RTPFramer framer = new RTPFramer();
    private final Map<Long, List<RtpPacket>> rtpStreams = new HashMap<Long, List<RtpPacket>>();

    private static FileWriter summaryWriter;

    private String fileName = "";
    private String displayName = "";
    private String orgCallid = "";
    private String callSid = "";

    @Override
    public void nextPacket(final Packet packet) throws IOException {
        try {
            if (packet.hasProtocol(Protocol.SIP)) {
                final SipPacket sip = (SipPacket) packet.getPacket(Protocol.SIP);
                // parse SIP from and x-orig-call-id
                if (sip.isRequest() && sip.isInvite()) {
                    final FromHeader from = sip.getFromHeader();
                    this.displayName = from.getAddress().getDisplayName().toString();
                    this.orgCallid = sip.getHeader(SIP_HEADER_ORG_CALL_ID).getValue().toString();
                    this.callSid = sip.getHeader(SIP_HEADER_CALL_SID).getValue().toString();
                } else if (sip.isResponse() && sip.toResponse().getStatus() == 200) {
                    this.callSid = sip.getHeader(SIP_HEADER_CALL_SID).getValue().toString();
                }
            } else if (packet.hasProtocol(Protocol.UDP)) {
                final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                final Buffer payload = udp.getPayload();

                // Take only RTP packet.
                // TODO: Is there better to filter only RTP?
                if (payload.getByte(0) == (byte) (0x80)) {

                    final RtpPacket rtp = this.framer.frame(udp, payload);
                    final int pt = rtp.getPayloadType();
                    if (pt < 0 || pt > 127) {
                        System.err.println("RTP payload type is not 0--127: " + pt);
                        return;
                    } else if (pt >= 72 && pt <= 76) {
                        System.err.println("RTCP packet: " + pt);
                        return;
                    }

                    final long ssrc = rtp.getSyncronizationSource();
                    List<RtpPacket> stream = this.rtpStreams.get(ssrc);
                    if (stream == null) {
                        stream = new ArrayList<RtpPacket>();
                        this.rtpStreams.put(ssrc, stream);
                    }
                    stream.add(rtp);
                }
            }
        } catch (final Exception e) {
            // e.printStackTrace();
        }
    }

    public void dumpStats() throws IOException {
        printValueToSummary(this.displayName);
        printValueToSummary(this.callSid);
        printValueToSummary(this.fileName);
        printValueToSummary(this.orgCallid);
        printValueToSummary("" + this.rtpStreams.size());
    }

    public void analyze() throws Exception {
        for (final List<RtpPacket> stream : this.rtpStreams.values()) {
            analyzeStream(stream);
        }
    }

    private void analyzeStream(final List<RtpPacket> stream) throws Exception {

        final ArrayList<RtpPacket> addtionalRtpList = new ArrayList<RtpPacket>();
        RtpPacket firstPacket = null;
        RtpPacket lastPacket = null;
        int lastAdditionalSeq = 0;
        int markerBits = 0;

        long maxTimeSkew = Long.MIN_VALUE;
        long minTimeSkew = Long.MAX_VALUE;
        RtpPacket maxPacket = null;
        RtpPacket minPacket = null;

        long totalTimeSkew = 0;
        int totalAdditional = 0;
        int totalCompensate = 0;

        String ssrcString = null;

        for (final RtpPacket pkt : stream) {
            if (firstPacket == null) {
                firstPacket = pkt;
                ssrcString = "0x" + Long.toHexString(firstPacket.getSyncronizationSource()).toUpperCase();
            }
            if (pkt.hasMarker()) {
                ++markerBits;
            }
            if (lastPacket != null) {

                // arrival time is in microsecond!
                final long wallTimeDiff = pkt.getArrivalTime() - lastPacket.getArrivalTime();
                final long delta = wallTimeDiff;
                final long rtpDelta = ((pkt.getTimestamp() - lastPacket.getTimestamp()) / 8) * 1000;
                final long timeSkew = rtpDelta - delta;

                // we only monitor rtp comes in order because we don't want to
                // implement jitter buffer here.
                if (lastPacket.getSeqNumber() + 1 == pkt.getSeqNumber()) {
                    // valid time skew is between 0.01 ms to 10 sec
                    if (delta >= 0 && Math.abs(timeSkew) < 10000000 && Math.abs(timeSkew) > 10) {
                        totalTimeSkew += timeSkew;
                        if (maxTimeSkew < totalTimeSkew) {
                            maxTimeSkew = totalTimeSkew;
                            maxPacket = pkt;
                        }
                        if (minTimeSkew > totalTimeSkew) {
                            minTimeSkew = totalTimeSkew;
                            minPacket = pkt;
                        }
                    }
                }

                // if we see a packet comes less than 15 ms after the previous,
                // and the sequence number is +1 of the previous,
                // put it into the list and print previous and this packet to
                // the file
                if (wallTimeDiff < 15000) {
                    if (lastAdditionalSeq + 1 == pkt.getSeqNumber()) {
                        ++totalAdditional;
                        addtionalRtpList.add(pkt);
                    }
                    lastAdditionalSeq = pkt.getSeqNumber();
                }
                if (wallTimeDiff > 35000) {
                    ++totalCompensate;
                }
            }
            lastPacket = pkt;
        }

        final long durationWallClock = (stream.get(stream.size() - 1).getArrivalTime() - stream.get(0).getArrivalTime()) / 1000;
        final long durationPkts = stream.size() * 20;
        final long durationDiff = durationPkts - durationWallClock;
        final int pt = stream.get(0).getPayloadType();

        printValueToSummary(String.format("0x%X", firstPacket.getSyncronizationSource()));
        printValueToSummary(firstPacket.getSourceIP() + ":" + firstPacket.getSourcePort());
        printValueToSummary("" + pt);
        printValueToSummary("" + durationWallClock);
        printValueToSummary("" + totalTimeSkew / 1000.0);
        printValueToSummary("" + maxTimeSkew / 1000.0);
        printValueToSummary("" + durationDiff);
    }

    public static void printValueToSummary(final String text) throws IOException {
        summaryWriter.write(text + ", ");
        System.out.print(text + ", ");
    }

    public static void printNewLineToSummary() throws IOException {
        summaryWriter.write("\n");
        System.out.println("");
    }

    public static void main(final String[] args) throws Exception {

        String dir = "";

        if (args.length >= 1) {
            dir = args[0];
        } else {
            System.out.println("Need at least one parameter for directory path.");
            System.exit(1);
        }

        final File folder = new File(dir);
        final File[] files = folder.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(final File dir, final String name) {
                return name.endsWith(".pcap");
            }
        });

        // final File[] files = new File[] { new File(dir) };

        summaryWriter = new FileWriter(new File("bulk-pcap-stat.csv"), true);

        for (final File file : files) {
            final Pcap pcap = Pcap.openStream(file);
            final BulkPcapStat oneOff = new BulkPcapStat();
            oneOff.fileName = file.getAbsolutePath();

            pcap.loop(oneOff);
            oneOff.dumpStats();
            oneOff.analyze();
            printNewLineToSummary();
        }

        summaryWriter.close();
    }
}
