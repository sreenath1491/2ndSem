import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;

public class PartA {
	
	public static void main(String[] args) {
		PartA partA = new PartA();
		partA.run("../http_first_sample.pcap");
	}
	
	public Map<FlowKey, List<Mydata>> run(String filename){
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(filename, errbuf);
		if(pcap == null){
			System.err.println(errbuf);
			return null;
		}

		JScanner.getThreadLocal().setFrameNumber(0);  
        PcapPacket packet = new PcapPacket(JMemory.POINTER);
        // exclude the ethernet source and destination addresses and etherType
        int bufferOffset = 14;
        byte[] etherType ;
        byte[] data;
        int headerLength;
        String srcIp;
        String destIp;
        String srcPort;
        String destPort;
        int tcpHStart;
        FlowKey flowKey;
        List<Mydata> flowVal;
        Map<FlowKey, List<Mydata>> tcpFlowMap = new HashMap<>(); 
        try{
	        while(pcap.nextEx(packet) == Pcap.NEXT_EX_OK) { 
	        	//extracting etherType from input. The 13th and 14th byte of packet represent the etherType
	        	etherType = packet.getByteArray(bufferOffset-2, 2);
	        	if(!isIp(etherType)){
	        		// no need to evaluate this packet . since it is not IP
	        		continue;
	        	}
	        	// now get the Ip packet
	        	data = packet.getByteArray(bufferOffset, packet.size()-bufferOffset);
	        	// next we need to check for tcp protocol.
	        	if(!isTcp(data)){
	        		// no need to evaluate this packet . since it is not TCP
	        		continue;
	        	}
	        	// next we need to get the header length to know where the tcp header starts from
	        	// this would be the rightmost 4 bits of the first byte of Ip packet. 
	        	headerLength = (data[0] & 0x0F);
	        	
	        	//Src Ip is 4 bytes starting from the 13th byte of Ip packet.
	        	srcIp = extractIp(data, 12).trim();
	        	
	        	//Dest Ip is 4 bytes starting from the 17th byte of Ip packet.
	        	destIp = extractIp(data, 16).trim();
	        	
	        	// calculate the tcp Header start point based on header length.
	        	// from now on data from tcp header will be retrieved using this value.
	        	tcpHStart = headerLength *4;
	        	
	        	//Src port is the first 2 bytes of the tcp header
	        	srcPort = extractPort(data, tcpHStart).trim();
	        	
	        	//Dest port is 2 bytes starting from the 3rd byte of tcp header
	        	destPort = extractPort(data, tcpHStart+2).trim();
	        	

	        	// sequence number - 4 bytes starting from  5th byte of tcp header
	        	long seqNo = extractSeqOrAckNo(data, tcpHStart+4);
	        	// ackNo - 4 bytes starting from  9th byte of tcp header
	        	long ackNo = extractSeqOrAckNo(data, tcpHStart+8);
	        	// winsize
	        	long winSize = extractWinSize(data, tcpHStart+14);
	        	//get syn, ack, fin flags
	        	boolean ack = ((data[tcpHStart+13] & 0x10) == 0x10);
	        	boolean syn = ((data[tcpHStart+13] & 0x02) == 0x02);
	        	boolean fin = ((data[tcpHStart+13] & 0x01) == 0x01);
	        	
	        	//flow map to track a tcp flow
	        	flowKey = new FlowKey(srcIp , destIp, srcPort, destPort);
	        	Mydata mydata = new Mydata(srcIp, destIp, srcPort, destPort, seqNo, ackNo, winSize, syn, ack, fin);
	        	if(!tcpFlowMap.containsKey(flowKey) && syn && !ack){
	        		flowVal = new ArrayList<>();
	        		mydata.forward = true;
	        		flowVal.add(mydata);
	        		tcpFlowMap.put(flowKey, flowVal);
	        	}
	        	else if(tcpFlowMap.containsKey(flowKey)){
	        		flowVal = tcpFlowMap.get(flowKey);
	        		if(flowVal.get(0).srcIp.equals(mydata.srcIp)){
	        			mydata.forward = true;
	        		}
	        		else{
	        			mydata.forward = false;
	        		}
	        		flowVal.add(mydata);
	        	}
	        	//int first2 = ((data[0] & 0xF0) >> 4);
	        }  
	        printData(tcpFlowMap);
        }finally{
			pcap.close();
		}
        return tcpFlowMap;
	}
	
	private static void printData(Map<FlowKey, List<Mydata>> tcpFlowMap) {
		System.out.println("Number of complete tcp flows:"+tcpFlowMap.size());
		int i = 1;
		for(Map.Entry<FlowKey, List<Mydata>> entry : tcpFlowMap.entrySet()){
			List<Mydata> flowData = entry.getValue();
			if(flowData != null && flowData.size() > 0 ){
				System.out.println("FLOW "+i+":");
				i++;
				int forward = 0;
				long relativeSeq = 0;
				long relativeAck = 0;
				for(int j = 0; j< flowData.size(); j++){
					Mydata mydata = flowData.get(j);
					if( j== 0){
						relativeSeq = mydata.seqNo;
					}
					if(j == 1){
						relativeAck = mydata.seqNo;
					}
					
					if(mydata.forward){
						System.out.println((j+1)+")"+mydata.toString(relativeSeq, relativeAck));
						forward++;
					}
					else{
						System.out.println((j+1)+")"+mydata.toString(relativeAck, relativeSeq));
					}
				}
				int reverse = flowData.size()-forward;
				System.out.println("Summary: Tcp forward/reverse/total packets: ["+forward+"/"+reverse+"/"+flowData.size()+"]");
			}
		}
		
	}

	private long extractWinSize(byte[] data, int start){
		byte[] winSizeBytes = extractBytes(data, start, 2);
		String hexWinSize = convertByteToHex(winSizeBytes);
		return Long.parseLong(hexWinSize, 16);
	}
	
	private long extractSeqOrAckNo(byte[] data, int start){
		byte[] seqNoBytes = extractBytes(data, start, 4);
		String hexSeqNo = convertByteToHex(seqNoBytes);
		return Long.parseLong(hexSeqNo, 16);
	}
	
	private byte[] extractBytes(byte[] data, int start, int length){
		byte[] result = new byte[length];
		for(int i =0; i< length; i++){
			result[i] = data[i+start];
		}
		return result;
	}

	private String extractPort(byte[] data, int start) {
		byte[] ipBytes = extractBytes(data, start, 2);
		String hexPort = convertByteToHex(ipBytes);
		return String.valueOf(Integer.parseInt(hexPort, 16));
	}
	
	private String extractIp(byte[] data, int start) {
		byte[] ipBytes = extractBytes(data, start, 4);
		String hexIp = convertByteToHex(ipBytes);
		StringBuffer ip = new StringBuffer();
		for(int i = 0; i < hexIp.length(); i = i+2 ){
			ip.append(Integer.parseInt(hexIp.substring(i, i+2), 16));
			ip.append(".");
		}
		return ip.substring(0, ip.length()-1).toString();
	}

	private boolean isTcp(byte[] input){
		byte[] protocol = new byte[1];
		// extracting protocol from input. Protocol is stored in the 10th byte of an IP packet
		protocol[0] = input[9];
		// for tcp the value is 0x06
		if("06".equals(convertByteToHex(protocol))){
			return true;
		}
		return false;
	}
	
	
	private boolean isIp(byte[] input){
		// etherType should be 0x0800 in our case
		if("0800".equals(convertByteToHex(input))){
			return true;
		}
		return false;
	}
	
	private String convertByteToHex(byte[] byteData){
		String val = DatatypeConverter.printHexBinary(byteData);
		return val;
	}
	
	
	class FlowKey{
		public String srcIp;
		public String destIp;
		public String srcPort;
		public String destPort;
		
		public FlowKey(String srcIp, String destIp, String srcPort, String destPort){
			this.srcIp = srcIp;
			this.destIp = destIp;
			this.srcPort = srcPort;
			this.destPort = destPort;
		}
		
	    @Override
	    public int hashCode() {
	        return srcIp.hashCode() + destIp.hashCode() + srcPort.hashCode()+ destPort.hashCode();
	    }

	    @Override
	    public boolean equals(Object obj) {
	        if (this == obj)
	            return true;
	        if (obj == null)
	            return false;
	        if (getClass() != obj.getClass())
	            return false;
	        final FlowKey other = (FlowKey) obj;
	        if(!(srcIp.equals(other.srcIp) || srcIp.equals(other.destIp))){
	        	return false;
	        }
	        if(!(destIp.equals(other.srcIp) || destIp.equals(other.destIp))){
	        	return false;
	        }
	        if(!(srcPort.equals(other.srcPort) || srcPort.equals(other.destPort))){
	        	return false;
	        }
	        if(!(destPort.equals(other.srcPort) || destPort.equals(other.destPort))){
	        	return false;
	        }
	        return true;
	    }
	    
	    public String toString(){
	    	return srcIp+"."+srcPort+"-->"+destIp+"."+destPort;
	    }
	}
	
	class Mydata{
		String srcIp;
		String destIp;
		String srcPort;
		String destPort;
		long seqNo;
		long ackNo;
		long winSize;
		boolean syn;
		boolean ack;
		boolean fin;
		boolean forward;
		
		public Mydata(String srcIp, String destIp, String srcPort, String destPort, long seqNo, long ackNo, long winSize, boolean syn, boolean ack, boolean fin){
			this.srcIp = srcIp;
			this.destIp = destIp;
			this.srcPort = srcPort;
			this.destPort = destPort;
			this.seqNo = seqNo;
			this.ackNo = ackNo;
			this.winSize = winSize;
			this.syn = syn;
			this.ack = ack;
			this.fin = fin;
		}
		
		public String toString(long relativeSeq, long relativeAck){
			StringBuffer sb  = new StringBuffer();
			sb.append(srcIp);
			sb.append(":");
			sb.append(srcPort);
			sb.append("-->");
			sb.append(destIp);
			sb.append(":");
			sb.append(destPort);
			sb.append("###");
			sb.append(". Sequence No: "+(seqNo-relativeSeq));
			sb.append(". Ack No: "+(ackNo-relativeAck));
			sb.append(". Window Size: "+winSize);
			sb.append(". Flags: ");
			if(syn)
				sb.append("SYN ");
			if(ack)
				sb.append(" ACK");
			if(fin)
				sb.append(" FIN");
			
			return sb.toString();
		}
	}

}
