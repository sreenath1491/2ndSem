import java.util.List;
import java.util.Map;

public class PartB extends PartA{

	public PartB(int part) {
		super(part);
	}

	public static void main(String[] args) {
		PartB partB = new PartB(PART_B);
		Map<FlowKey, List<Mydata>> tcpFlowMap = partB.run("../HTTP_SampleB.pcap");
		partB.printData(tcpFlowMap);
		System.out.println("ANALYSIS:-----------------------------------------");
		partB.runAnalysis(tcpFlowMap);
		
	}
	
	public void runAnalysis(Map<FlowKey, List<Mydata>> tcpFlowMap){
		int i = 1;
		long avg = 0;
		int count = 0;
		long prev = -1;
		long totalData = 0;
		for(Map.Entry<FlowKey, List<Mydata>> entry : tcpFlowMap.entrySet()){
			List<Mydata> flowData = entry.getValue();
			//1st packet is forward packet i.e a syn packet
			avg = 0;
			count = 0;
			prev = flowData.get(0).tsVal;
			totalData = flowData.get(0).dataLen;
			for(int j= 1; j< flowData.size(); j++){
				Mydata mydata = flowData.get(j);
				totalData += mydata.dataLen;
				//totalData += mydata.
				if(mydata.forward && mydata.tsVal >0){
					if(mydata.tsVal-prev == 0){
						//if diff is 0 they are request packets being sent back to back.So skip them
						continue;
					}
					avg+=mydata.tsVal-prev;
					prev = mydata.tsVal; 
					count++;	
				}
			}
			System.out.println("FLOW "+i+"  Avg RTT:"+(float)avg/count +" milliSec");
			System.out.println("FLOW "+i+" Throughput:"+(float)(totalData*8)/(avg)+" bits/milliSec");
			System.out.println("FLOW "+i+" ICWND:"+ printICW(flowData.get(0).mss)+" bytes");
			i++;
		}
	}
	
	private long printICW(long bytes){
	   if (bytes <= 1095)
           return 4 * bytes;
       if (bytes > 1095 && bytes <= 2190)
    	   return 3*bytes;
       if (bytes > 2190)
    	   return 2 * bytes;
       return -1;
	}
	
	@Override
	public void printData(Map<FlowKey, List<Mydata>> tcpFlowMap) {
		System.out.println("Number of complete tcp flows:"+tcpFlowMap.size());
		int i = 1;
		for(Map.Entry<FlowKey, List<Mydata>> entry : tcpFlowMap.entrySet()){
			List<Mydata> flowData = entry.getValue();
			if(flowData != null && flowData.size() > 0 ){
				System.out.println("FLOW "+i+":\n");
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
						System.out.println(mydata.toStringPartB(relativeSeq, relativeAck));
						forward++;
					}
					else{
						System.out.println(mydata.toStringPartB(relativeAck, relativeSeq));
					}
				}
				int reverse = flowData.size()-forward;
				System.out.println("Summary: Tcp forward/reverse/total packets: ["+forward+"/"+reverse+"/"+flowData.size()+"]");
			}
		}
	}
	
}
