import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class MyDig {
	private int rootIndex = -1;
	private int rootsQueried = 0;
	private long start;
	private int type;
	private static final String ROUND_ROBIN_FILE = "rrData.txt";
	
	public MyDig(){
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
		if (args.length < 2 ){
			System.out.println("Please provide a valid domain name and type");
			return;
		}
		
		MyDig myDig = new MyDig();
		String type = args[1];
		if("A".equals(type))
			myDig.type = Type.A;
		else if("NS".equals(type))
			myDig.type = Type.NS;
		else if("MX".equals(type))
			myDig.type = Type.MX;
		else{
			System.out.println("Invalid Type.Please provide a valid type - A, NS, MX");
			return;
		}
		
		String results = myDig.run(args[0]);
		if(results == null){
			System.out.println("ERROR");
		}
		else{
			System.out.println(results);
		}
	}
	
	private String run(String domain) {
		File f;
		start = System.currentTimeMillis();
		try{
			f = new File(ROUND_ROBIN_FILE);
			readFile(f);
		}
		catch(Exception e){
			System.out.println("Error occurred while reading file");
			return null;
		}

		String input = domain;
		if(!input.endsWith(".")){
			input = input + ".";
		}
		String results = queryAllRoots(input);

		try{
			updateFile(f);
		}
		catch(Exception e){
			System.out.println("File root index update failed");
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
	
	private String queryAllRoots(String input){
		String root;
		String result = null;
		while(result == null && rootsQueried < rootList.size()){
			rootIndex = (rootIndex +1)%13;
			root = rootList.get(rootIndex);
			result = getFinalAddress(root, input);
			rootsQueried++;
		}
		return result;
	}
	
	
	private String getFinalAddress(String address, String input){
		try{
			Record[] records;
			Resolver resolver;
			Name name;
			Record query;
			Message msg;
			Message resp = null;
			String root = address;
			while(true){
			    resolver = new SimpleResolver(address);
			    name = Name.fromString(input);
			    query = Record.newRecord(name, type, DClass.IN);
			    msg = Message.newQuery(query);
			    resp = resolver.send(msg);
		    	records = resp.getSectionArray(Section.AUTHORITY);
		    	Record[] answer = resp.getSectionArray(Section.ANSWER);
		    	if(answer.length > 0 ){
		    		for(Record r : answer){
		    			if(r instanceof CNAMERecord){
		    				Record[] cnameRec = getCnameAddress(root, ((CNAMERecord) r).getAlias().toString());
		    				if(cnameRec != null && cnameRec.length > 0){
		    					for(Record rec : cnameRec){
		    						resp.addRecord(rec, Section.ANSWER);
		    					}
		    				}
		    			}
		    		}
		    		break;
		    	}
		    	if(records[0] instanceof SOARecord){
		    		break;
		    	}
		    	address = ((NSRecord) records[0]).getAdditionalName().toString();
			}
			long end = System.currentTimeMillis();
			long duration = end -start;
			return genResp(resp.toString(), duration);
		}
		catch(Exception e){
			return null;
		}
	}
	
	private String genResp(String resp, long duration){
		DateFormat dateFormat = new SimpleDateFormat("E MMM dd HH:mm:ss z yyyy");
		Date date = new Date();
		resp = resp + "\n" + ";; Query time: "+ duration +" msec\n;; When: "+dateFormat.format(date);
		return resp;
	}
	
	private Record[] getCnameAddress(String address, String input){
		try{
			Record[] records;
			Resolver resolver;
			Record[] answer = null;
			Name name;
			Record query;
			Message msg;
			Message resp = null;
			while(true){
			    resolver = new SimpleResolver(address);
			    name = Name.fromString(input);
			    query = Record.newRecord(name, type, DClass.IN);
			    msg = Message.newQuery(query);
			    resp = resolver.send(msg);
		    	records = resp.getSectionArray(Section.AUTHORITY);
		    	answer = resp.getSectionArray(Section.ANSWER);
		    	if(answer.length > 0){
		    		break;
		    	}
		    	if(records.length >0 && records[0] instanceof SOARecord){
		    		break;
		    	}
		    	address = ((NSRecord) records[0]).getAdditionalName().toString();
			}
			return answer;
		}
		catch(Exception e){
			return null;
		}
	}
}