import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.xbill.DNS.Address;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class MyDig {
	private int rootIndex = -1;
	private int rootsQueried = 0;
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
			myDig.type = Type.NS;
		else if("NS".equals(type))
			myDig.type = Type.NS;
		else if("MX".equals(type))
			myDig.type = Type.MX;
		else{
			System.out.println("Invalid Type.Please provide a valid type");
			return;
		}
		
		String results = myDig.run("www.facebook.com");
		if(results == null){
			System.out.println("ERROR");
		}
		else{
			System.out.println(results);
		}
		
		InetAddress addr = Address.getByName(args[0]);
		System.out.println(addr);
	}
	
	private String run(String domain) {
		File f;
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
		int dots = input.length() - input.replace(".", "").length() + 1;
		String results = queryAllRoots(input, dots);

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
	
	private String queryAllRoots(String input, int dots){
		String root;
		String result = null;
		while(result == null && rootsQueried < rootList.size()){
			rootIndex = (rootIndex +1)%13;
			root = rootList.get(rootIndex);
			result = getFinalAddress(root, input, dots);
			rootsQueried++;
		}
		return result;
	}
	
	
	private String getFinalAddress(String address, String input, int dots){
		try{
			Record[] records;
			Resolver resolver;
			Name name;
			Record query;
			Message msg;
			Message resp = null;
			int rcode = -1;
			while(dots > 0){
			    resolver = new SimpleResolver(address);
			    name = Name.fromString(input);
			    query = Record.newRecord(name, type, DClass.IN);
			    msg = Message.newQuery(query);
			    resp = resolver.send(msg);
			    rcode = resp.getRcode();
			    if(rcode == Rcode.NXDOMAIN){
			    	System.out.println("Invalid Domain.Please provide a valid domain");
			    	System.exit(-1);
			    }
			    if(dots > 1){
			    	records = resp.getSectionArray(Section.AUTHORITY);
			    	if(records[0] instanceof SOARecord){
			    		break;
			    	}
			    	address = ((NSRecord) records[0]).getAdditionalName().toString();
			    }

			    dots--;
			}
			return resp.toString();
	    	//records = resp.getSectionArray(Section.ANSWER);
/*			if (rcode == Rcode.NOERROR)
				return resp.toString();
			else
				return null;*/
		}
		catch(Exception e){
			return null;
		}
	}
}



/*
 * 
			    	records = resp.getSectionArray(Section.AUTHORITY);
			    	Record[]  ans = resp.getSectionArray(Section.ANSWER);
			    	if(ans.length > 0 && ans[0] instanceof CNAMERecord){
			    		input = ((CNAMERecord) ans[0]).getAlias().toString();
			    	}
			    	else if(records[0] instanceof SOARecord){
			    		break;
			    	}
			    	else
			    		address = ((NSRecord) records[0]).getAdditionalName().toString();
			    */


/*
 * old
 			    if(dots > 1){
			    	records = resp.getSectionArray(Section.AUTHORITY);
			    	if(records[0] instanceof SOARecord){
			    		break;
			    	}
			    	address = ((NSRecord) records[0]).getAdditionalName().toString();
			    }
			 */
