import java.util.List;
import java.util.Map;

public class PartC extends PartA {

	public PartC(int part) {
		super(part);
		// TODO Auto-generated constructor stub
	}
	
	public static void main(String[] args) {
		PartC partC = new PartC(PART_B);
		Map<FlowKey, List<Mydata>> tcpFlowMap = partC.run("../HTTP_Sample_Big_Packet.pcap");
		partC.runAnalysis(tcpFlowMap);
		
	}
	
	public void runAnalysis(Map<FlowKey, List<Mydata>> tcpFlowMap){
		float rtt = 0;
		long prev = -1;
		int count = 0;
		double srtt =0;
		double rttVar =0;
		double rto = 0;
		int g = 1;
		int k =4;
		double alpha = 0.125;
		double beta = 0.25;
		for(Map.Entry<FlowKey, List<Mydata>> entry : tcpFlowMap.entrySet()){
			List<Mydata> flowData = entry.getValue();
			//1st packet is forward packet i.e a syn packet
			rtt = 0;
			prev = flowData.get(0).tsVal;
			for(int j= 1; j< flowData.size(); j++){
				Mydata mydata = flowData.get(j);
				if(mydata.forward && mydata.tsVal >0){
					if(mydata.tsVal-prev == 0){
						//if diff is 0 they are request packets being sent back to back.So skip them
						continue;
					}
					rtt = mydata.tsVal-prev;
					prev = mydata.tsVal;
					if(count == 0){
						srtt = rtt;
						rttVar = rtt/2;
					}
					else if(count == 1 || count == 2){
						srtt = rtt;
						rttVar = rtt/2;
						rttVar = (1-beta)*rttVar + beta * Math.abs(srtt - rtt);
						srtt = (1-alpha) * srtt + alpha*rtt;
					}
					else{
						break;
					}
					rto = srtt + Math.max(g, k*rttVar);
					count++;
					System.out.println("RTO "+count+" : "+rto);
				}
			}			
		}
	}

}
