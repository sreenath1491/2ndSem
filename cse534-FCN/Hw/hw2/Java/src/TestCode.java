import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Tcp;

public class TestCode {
	
	public static void main(String[] args) {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline("../http_first_sample.pcap",errbuf);
		if(pcap == null){
			System.err.println(errbuf);
			return;
		}
        JScanner.getThreadLocal().setFrameNumber(0);  
        final Tcp tcp = new Tcp(); 
        final PcapPacket packet = new PcapPacket(JMemory.POINTER);  
        final Map<JFlowKey, JFlow> flows = new HashMap<JFlowKey, JFlow>();  
//        JFlowMap map = new JFlowMap();  
//        
//        pcap.loop(Pcap.LOOP_INFINITE, map, null);  
//  
//        System.out.println(map.toString());
/*
        while(pcap.nextEx(packet) == 1) {  
            final JFlowKey key = packet.getState().getFlowKey();  
  
            JFlow flow = flows.get(key);  
            if (flow == null) {  
                flows.put(key, flow = new JFlow(key));  
            }  
            flow.add(new PcapPacket(packet));  
        }  
  
        for (JFlow flow : flows.values()) {  
            if (flow.isReversable()) {  
                List<JPacket> forward = flow.getForward();  
                for (JPacket p : forward) {  
                    System.out.printf("%d, ", p.getFrameNumber());  
                }  
                System.out.println();  
  
                List<JPacket> reverse = flow.getReverse();  
                for (JPacket p : reverse) {  
                    System.out.printf("%d, ", p.getFrameNumber()); 
                    if(p.hasHeader(tcp)){
                    	p.getHeader(tcp);
                    	System.out.println(tcp.toString());
                    }
                }  
            } else {  
                for (JPacket p : flow.getAll()) {  
                    System.out.printf("%d, ", p.getFrameNumber());  
                }  
            }  
            System.out.println();  
        } */
        String a = "123";
        String b = new String("123");
        System.err.println(a.hashCode());
        System.err.println(b.hashCode());
        System.err.println(a==b);
        System.err.println(a.equals(b));
        
        
        
        
		
		pcap.close();
	}

}
