package net.neferett.packetsniffer;

import lombok.Data;
import lombok.SneakyThrows;
import org.pcap4j.core.*;

import java.util.List;

@Data
public class Main {

    static final String filename = "packets_sniffed.pcap";

    private PcapNetworkInterface device;
    private PcapHandle handle;
    private PcapDumper dumper;

    private final int maxLength = 65536;
    private final int timeout = 1;
    private final String filter = "tcp";
    private final int maxPackets = 10;

    @SneakyThrows
    private PcapNetworkInterface selectDevice() {
        List<PcapNetworkInterface> allDevices = Pcaps.findAllDevs();
        if (allDevices.size() == 0)
            return null;

        return allDevices.get(0);

    }

    @SneakyThrows
    private void handlingPackets() {
        this.handle = this.device.openLive(this.maxLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, this.timeout);
        this.dumper = this.handle.dumpOpen(filename);

        this.handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        this.handle.loop(this.maxPackets, this.createPacketListener());
    }

    @SneakyThrows
    private PacketListener createPacketListener() {
        return (packet) -> {
            try {
                this.dumper.dump(packet, this.handle.getTimestamp());
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        };
    }

    @SneakyThrows
    private void launchSniffing() {
        this.device = this.selectDevice();
        System.out.println("Device selected successfully");
        System.out.println(this.device);

        if (device == null) {
            System.out.println("No device connected, please try again.");
            return;
        }

        System.out.println("Packet sniffing running, please wait a moment.");
        // Will lock until maxPackets
        this.handlingPackets();

        // Once loop unlocked we print stats
        PcapStat stats = this.handle.getStats();
        System.out.println("Packets received: " + stats.getNumPacketsReceived());
        System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
        System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());

        //Closing dumper and handler
        this.dumper.close();
        this.handle.close();
    }

    public static void main(String[] args) {
        Main main = new Main();

        main.launchSniffing();

        System.out.println("All packets sniffed dumped in " + filename);
    }
}
