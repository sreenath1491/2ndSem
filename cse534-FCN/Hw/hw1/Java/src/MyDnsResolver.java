import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.Address;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class MyDnsResolver {
	private int rootIndex = -1;
	private int rootsQueried = 0;
	private static final String ROUND_ROBIN_FILE = "rrData.txt";
	
	public MyDnsResolver(){
		rootIndex = -1;
		rootsQueried = 0;
	}
	
	private static List<String> rootList = new ArrayList<>(); 
	static{
		rootList.add("a.root-servers.net");
		rootList.add("b.root-servers.net");
		rootList.add("c.root-servers.net");
		rootList.add("d.root-servers.net");
		rootList.add("e.root-servers.net");
		rootList.add("f.root-servers.net");
		rootList.add("g.root-servers.net");
		rootList.add("h.root-servers.net");
		rootList.add("i.root-servers.net");
		rootList.add("j.root-servers.net");
		rootList.add("k.root-servers.net");
		rootList.add("l.root-servers.net");
		rootList.add("m.root-servers.net");
	}
	
	public static void main(String[] args) throws Exception {
		if (args.length == 0 || args[0] == null || args[0] == "" ){
			System.out.println("Please provide a valid domain name");
			return;
		}
		MyDnsResolver myDnsResolver = new MyDnsResolver();
		
		
		ArrayList<String> results = myDnsResolver.run("www.facebook.org");
		if(results.size() == 0){
			System.out.println("ERROR: Could not obtain the ip address of input");
		}
		else{
			for(String s : results){
				System.out.println(s.split("/")[1]);
			}
		}
		
		InetAddress addr = Address.getByName("www.facebook.com");
		System.out.println(addr);
	}
	
	private ArrayList<String> run(String domain) {
		File f;
		try{
			f = new File(ROUND_ROBIN_FILE);
			readFile(f);
		}
		catch(Exception e){
			System.out.println("Error occurred while reading file");
			return new ArrayList<String>();
		}

		String input = domain;
		if(!input.endsWith(".")){
			input = input + ".";
		}
		//int dots = input.length() - input.replace(".", "").length();
		Record[] records = queryAllRoots(input);
		ArrayList<String> results = getResults(records);

		try{
			updateFile(f);
		}
		catch(Exception e){
			System.out.println("File root index update failed");
		}
		
		return results;
	}
	
	private ArrayList<String> getResults(Record[] records ){
		boolean cnameExits = false;
		String input = null;
		int dots = 0;
		ArrayList<String> results = new ArrayList<>();
		if(records != null){
			for(Record rec : records){
				if(rec instanceof ARecord)
					results.add(((ARecord) rec).getAddress().toString());
//				else{ //only 1 cname can exist
//					input = ((CNAMERecord) rec).getAlias().toString();
//					dots  = input.length() - input.replace(".", "").length();
//					cnameExits = true;
//				}
			}
//			if(!cnameExits){
//				break;
//			}
//			else{
//				rootsQueried = 0;
//				records = queryAllRoots(input, dots);
//				cnameExits = false;
//			}
		}
		return results;
	}
	
	private void readFile(File f) throws IOException{
		if(f.exists()){
			FileReader fr = new FileReader(f);
			BufferedReader br = new BufferedReader(fr);
			String line = br.readLine();
			rootIndex = Integer.valueOf(line);
			rootsQueried = 0;
			br.close();
			fr.close();
		}
		else{
			rootIndex = 0;
			rootsQueried = 0;
		}
	}

	private void updateFile(File f) throws IOException{
		if(!f.exists()){
			f.createNewFile();
			System.out.println("File for round robin scheduling is created at :"+f.getAbsolutePath());
		}
		FileWriter fw = new FileWriter(f);
		fw.write(String.valueOf(rootIndex));
		fw.write("\n");
		fw.write("Last used root: "+rootList.get(rootIndex));
		fw.flush();
		fw.close();
	}
	
	private Record[] queryAllRoots(String input){
		String root;
		Record[] records = null;
		while((records == null || records.length == 0)&& rootsQueried < rootList.size()){
			rootIndex = (rootIndex +1)%13;
			root = rootList.get(rootIndex);
			records = getFinalAddress(root, input);
			rootsQueried++;
			//System.out.println("Query number: "+rootsQueried);			
			//System.out.println("Query index: "+rootIndex);
		}
		
		return records;
	}
	
	
	private Record[] getFinalAddress(String address, String input){
		try{
			Record[] records;
			Resolver resolver;
			Name name;
			Record query;
			Message msg;
			Message resp = null;
			Record[] answer;
			while(true){
			    resolver = new SimpleResolver(address);
			    name = Name.fromString(input);
			    query = Record.newRecord(name, Type.A, DClass.IN);
			    msg = Message.newQuery(query);
			    resp = resolver.send(msg);
			    int rcode = resp.getRcode();
			    if(rcode == Rcode.NXDOMAIN){
			    	System.out.println("Invalid Domain.Please provide a valid domain");
			    	System.exit(-1);
			    }
			    records = resp.getSectionArray(Section.AUTHORITY);
			    answer = resp.getSectionArray(Section.ANSWER);
			    if(answer.length > 0 && answer[0] instanceof ARecord){
			    	break;
			    }
			    else if(answer.length > 0 && answer[0] instanceof CNAMERecord){
			    	input = ((CNAMERecord) answer[0]).getAlias().toString();
			    }
			    else if(records[0] instanceof NSRecord)
			    	address = ((NSRecord) records[0]).getAdditionalName().toString();
			    else {
			    	break;
			    }

			}
	    	//records = resp.getSectionArray(Section.ANSWER);
	    	return answer;
		}
		catch(Exception e){
			return null;
		}
	}
}
