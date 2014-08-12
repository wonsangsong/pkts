
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
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author jonas
 *
 */
public class PcapRtpStat implements PacketHandler {

    private final static boolean IS_DEBUG_MODE = true;
    private final static String SIP_HEADER_CALL_SID = "X-Twilio-CallSid";

    private final RTPFramer framer = new RTPFramer();
    private final Map<Long, List<RtpPacket>> rtpStreams = new HashMap<Long, List<RtpPacket>>();

    private static FileWriter summaryWriter;
    private static FileWriter detailWriter;

    private String displayName = "";
    private String callSid = "";

    private static StringBuilder sb;

    @Override
    public void nextPacket(final Packet packet) throws IOException {
        try {
            if (packet.hasProtocol(Protocol.SIP)) {
                final SipPacket sip = (SipPacket) packet.getPacket(Protocol.SIP);
                if (sip.isInvite() && sip.isRequest()) {
                    if (this.displayName.length() == 0) {
                        final FromHeader from = sip.getFromHeader();
                        this.displayName = from.getAddress().getDisplayName().toString();
                    }
                    if (this.callSid.length() == 0) {
                        this.callSid = sip.getHeader(SIP_HEADER_CALL_SID).getValue().toString();
                    }
                } else if (sip.isResponse() && sip.toResponse().getStatus() == 200) {
                    if (this.callSid.length() == 0) {
                        this.callSid = sip.getHeader(SIP_HEADER_CALL_SID).getValue().toString();
                    }
                }
            } else if (packet.hasProtocol(Protocol.UDP)) {
                final UDPPacket udp = (UDPPacket) packet.getPacket(Protocol.UDP);
                final Buffer payload = udp.getPayload();
                // Take only RTP packet.
                // TODO: Is there better to filter only RTP?
                if (payload.capacity() >= 12 && payload.getByte(0) == (byte) (0x80)) {
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
        printLineToSummary("CallSid: " + this.callSid);
        printLineToSummary("SIP DisplayName: " + this.displayName);
        printLineToSummary("Num of RTP streams: " + this.rtpStreams.size());
        for (final List<RtpPacket> stream : this.rtpStreams.values()) {
            printLineToSummary(String.format("0x%X count: %d, payload type: %d", stream.get(0).getSyncronizationSource(), stream.size(), stream.get(0).getPayloadType()));
        }
    }

    public void analyze() throws Exception {
        for (final List<RtpPacket> stream : this.rtpStreams.values()) {
            analyzeStream(stream);
        }
        if (!IS_DEBUG_MODE) {
            if (this.rtpStreams.size() == 0) {
                System.out.print(",No RTP Streams captured");
            }
        }
    }

    private void analyzeStream(final List<RtpPacket> stream) throws Exception {

        if (stream.size() < 2) {
            return;
        }

        final ArrayList<RtpPacket> addtionalRtpList = new ArrayList<RtpPacket>();
        RtpPacket firstPacket = null;
        RtpPacket lastPacket = null;
        int lastAdditionalSeq = 0;
        int markerBits = 0;

        long maxTimeSkew = Long.MIN_VALUE;
        long minTimeSkew = Long.MAX_VALUE;

        RtpPacket maxPacket = null;
        RtpPacket minPacket = null;

        boolean aroundDTMF = false;
        long maxRtpDelta = 0;
        long maxRtpSeq = 0;
        int totalRtpTsJump = 0;

        long totalTimeSkew = 0;
        int totalCompensate = 0;

        String ssrcString = null;

        for (final RtpPacket pkt : stream) {
            if (firstPacket == null) {
                firstPacket = pkt;
                ssrcString = "0x" + Long.toHexString(firstPacket.getSyncronizationSource()).toUpperCase();
                final String fname = ssrcString + ".txt";
                if (IS_DEBUG_MODE) {
                    detailWriter = new FileWriter(new File(fname), false);
                }
            }
            if (pkt.hasMarker()) {
                ++markerBits;
                //detailWriter.write(String.format("Marker [%d] ArrivalTime=%d Pt=%d SSRC=%s Seq=%d Ts=%d\n", (pkt.getArrivalTime() - firstPacket.getArrivalTime()) / 1000000, pkt.getArrivalTime() / 1000, pkt.getPayloadType(), ssrcString, pkt.getSeqNumber(), pkt.getTimestamp()));
            }

            if (lastPacket != null) {

                // arrival time is in microsecond!
                final long wallTimeDiff = pkt.getArrivalTime() - lastPacket.getArrivalTime();
                final long delta = wallTimeDiff;
                long rtpDelta = ((pkt.getTimestamp() - lastPacket.getTimestamp()) / 8) * 1000;
                if (rtpDelta < 0) {
                    rtpDelta = 20 * 1000;
                }
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

                    // count large rtp timestamp jump (over 10 seconds &
                    // timeskew is over 100ms and doesn't have marker bit).
                    if (rtpDelta > 10000000 && timeSkew > 100000 && !pkt.hasMarker()) {
                        totalRtpTsJump++;
                        maxRtpDelta = Math.max(maxRtpDelta, rtpDelta);
                        maxRtpSeq = pkt.getSeqNumber();
                        if (lastPacket.getPayloadType() == 101) {
                            aroundDTMF = true;
                        }
                        if (IS_DEBUG_MODE) {
                            detailWriter.write(String.format("# [%d] ArrivalTime=%d Pt=%d SSRC=%s Seq=%d Ts=%d Delta=%d RTP-Delta=%d Skew=%d Drift=%d\n", (pkt.getArrivalTime() - firstPacket.getArrivalTime()) / 1000000, pkt.getArrivalTime() / 1000, pkt.getPayloadType(), ssrcString, pkt.getSeqNumber(), pkt.getTimestamp(), delta / 1000, rtpDelta / 1000, timeSkew / 1000, totalTimeSkew / 1000));
                        }
                    }
                }

                if (pkt.getPayloadType() == 101 && lastPacket.getSeqNumber() == maxRtpSeq) {
                    aroundDTMF = true;
                }

                // if we see a packet comes less than 15 ms after the previous,
                // and the sequence number is +1 of the previous,
                // put it into the list and print previous and this packet to
                // the file
                if (wallTimeDiff < 15000) {
                    if (lastAdditionalSeq + 1 == pkt.getSeqNumber()) {
                        addtionalRtpList.add(pkt);
                    }
                    if (IS_DEBUG_MODE) {
                        detailWriter.write(String.format("+ [%d] ArrivalTime=%d Pt=%d SSRC=%s Seq=%d Ts=%d Delta=%d Skew=%d Drift=%d\n", (pkt.getArrivalTime() - firstPacket.getArrivalTime()) / 1000000, pkt.getArrivalTime() / 1000, pkt.getPayloadType(), ssrcString, pkt.getSeqNumber(), pkt.getTimestamp(), delta / 1000, timeSkew / 1000, totalTimeSkew / 1000));
                    }
                    lastAdditionalSeq = pkt.getSeqNumber();
                }
                if (wallTimeDiff > 35000) {
                    ++totalCompensate;
                    if (IS_DEBUG_MODE) {
                        detailWriter.write(String.format("- [%d] ArrivalTime=%d Pt=%d SSRC=%s Seq=%d Ts=%d Delta=%d Skew=%d Drift=%d\n", (pkt.getArrivalTime() - firstPacket.getArrivalTime()) / 1000000, pkt.getArrivalTime() / 1000, pkt.getPayloadType(), ssrcString, pkt.getSeqNumber(), pkt.getTimestamp(), delta / 1000, timeSkew / 1000, totalTimeSkew / 1000));
                    }
                }
            }
            lastPacket = pkt;
        }

        if (IS_DEBUG_MODE) {
            detailWriter.close();
        }

        final long durationWallClock = (stream.get(stream.size() - 1).getArrivalTime() - stream.get(0).getArrivalTime()) / 1000;
        final long durationPkts = stream.size() * 20;
        final long durationDiff = durationPkts - durationWallClock;

        printLineToSummary(String.format("==== 0x%X, %s:%d ====", firstPacket.getSyncronizationSource(), firstPacket.getSourceIP(), firstPacket.getSourcePort()));
        printLineToSummary("Marker bits: " + markerBits);
        printLineToSummary("Total time skew (ms)  : " + totalTimeSkew / 1000.0);
        if (maxPacket != null) {
            printLineToSummary("Max time skew (ms)    : " + maxTimeSkew / 1000.0 + " @ RTP seq: " + maxPacket.getSeqNumber() + ", position in sec: " + (maxPacket.getArrivalTime() - firstPacket.getArrivalTime()) / 1000000);
        }
        if (minPacket != null) {
            printLineToSummary("Min time skew (ms)    : " + minTimeSkew / 1000.0 + " @ RTP seq: " + minPacket.getSeqNumber() + ", position in sec: " + (minPacket.getArrivalTime() - firstPacket.getArrivalTime()) / 1000000);
        }
        printLineToSummary("Total wall clock (ms) : " + durationWallClock);
        printLineToSummary("Total samples (ms)    : " + durationPkts);
        printLineToSummary("Diff (ms)             : " + durationDiff);
        printLineToSummary("Diff from pkt (ms)    : " + addtionalRtpList.size() * 20);
        printLineToSummary("Extra pkts from diff  : " + durationDiff / 20);
        printLineToSummary("Extra pkts actual     : " + addtionalRtpList.size());
        printLineToSummary("Compensation pkts     : " + totalCompensate);
        printLineToSummary("Rtp ts jumps          : " + totalRtpTsJump);
        printLineToSummary("Rtp jump around DTMF  : " + aroundDTMF);

        if (!IS_DEBUG_MODE) {
            if (totalRtpTsJump > 0) {
                sb = new StringBuilder(",");
                sb.append(this.callSid).append(",");
                sb.append(ssrcString).append(",");
                sb.append(firstPacket.getSourceIP()).append(",");
                sb.append(firstPacket.getSourcePort()).append(",");
                sb.append(durationWallClock).append(",");
                sb.append(totalRtpTsJump).append(",");
                sb.append(maxRtpDelta).append(",");
                sb.append(aroundDTMF);
                System.out.println(sb.toString());
            }
        }
    }

    public static void printLineToSummary(final String text) throws IOException {
        if (IS_DEBUG_MODE) {
            summaryWriter.write(text + "\n");
            System.out.println(text);
        }
    }

    public static void main(final String[] args) throws Exception {

        // Step 1 - obtain a new Pcap instance by supplying an InputStream that
        // points
        // to a source that contains your captured traffic. Typically you may
        // have stored that traffic in a file so there are a few convenience
        // methods for those cases, such as just supplying the name of the
        // file as shown below.
        final String dir = "/Users/wsong/Twilio/project/bug-fix/VOICE-906/2013-10-31";
        final String file = "03ef614032a077623f1f2192c9a19fbd@10.196.26.223_HO2f119694f42e4d99881b97107b47a42a.pcap";

        String path = dir + "/" + file;
        if (args.length >= 1) {
            path = args[0];
        }
        String callid = "";
        if (args.length >= 2) {
            callid = args[1];
        }
        String desc = "";
        if (args.length >= 3) {
            desc = args[2];
        }

        Pcap pcap = null;
        final PcapRtpStat oneOff = new PcapRtpStat();

        try {
            pcap = Pcap.openStream(path);
        } catch (final FileNotFoundException e) {
            System.out.print(",No Pcap");
            System.exit(1);
        }

        if (IS_DEBUG_MODE) {
            summaryWriter = new FileWriter(new File("pcap-stat.txt"), true);
        }
        // Step 2 - Once you have obtained an instance, you want to start
        //          looping over the content of the pcap. Do this by calling
        //          the loop function and supply a PacketHandler, which is a
        //          simple interface with only a single method - nextPacket
        pcap.loop(oneOff);

        printLineToSummary("sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss");
        printLineToSummary("PCAP file  : " + path);
        printLineToSummary("CallSid    : " + callid);
        printLineToSummary("Description: " + desc);
        printLineToSummary("===============================================================================");

        oneOff.dumpStats();
        oneOff.analyze();
        printLineToSummary("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

        if (IS_DEBUG_MODE) {
            summaryWriter.close();
        }
    }
}
