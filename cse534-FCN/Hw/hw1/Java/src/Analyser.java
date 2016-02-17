import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class Analyser {
	
	private static List<String> alexaList = new ArrayList<>();
	static{
		alexaList.add("www.google.com");
		alexaList.add("www.facebook.com");
		alexaList.add("www.youtube.com");
		alexaList.add("www.baidu.com");
		alexaList.add("www.yahoo.com");
		alexaList.add("www.amazon.com");
		alexaList.add("www.wikipedia.com");
		alexaList.add("www.qq.com");
		alexaList.add("www.google.co.in");
		alexaList.add("www.twitter.com");
		alexaList.add("www.live.com");
		alexaList.add("www.taobao.com");
		alexaList.add("www.sina.com.cn");
		alexaList.add("www.msn.com");
		alexaList.add("www.yahoo.co.jp");
		alexaList.add("www.linkedin.com");
		alexaList.add("www.google.co.jp");
		alexaList.add("www.weibo.com");
		alexaList.add("www.bing.com");
		alexaList.add("www.vk.com");
		alexaList.add("www.yandex.ru");
		alexaList.add("www.hao123.com");
		alexaList.add("www.ebay.com");
		alexaList.add("www.instagram.com");
		alexaList.add("www.google.de");
	}
	
	private static Map<String, Long> data = new HashMap<>();
	
	public static void main(String[] args) throws InterruptedException, IOException {
		//MyDnsResolver myDnsResolver = new MyDnsResolver();
		//String dns = "130.245.255.4";
		String dns = "8.8.8.8";
		int k = 0;
		for(String s : alexaList){
			long avgTime = 0;
			System.out.println("Quering for: "+s);
			for(int i = 0; i < 10; i++){
				long time = query(s);
				avgTime += time;
			}
			System.out.println("Quering done: "+(k++));
			avgTime = avgTime/10;
			data.put(s, avgTime);
		}
		
		File f = new File("./partc-3.csv");
		if(!f.exists()){
			f.createNewFile();
			System.out.println("File for round robin scheduling is created at :"+f.getAbsolutePath());
		}
		FileWriter fw = new FileWriter(f);
		for(Map.Entry<String, Long> entry : data.entrySet()){
			fw.write(entry.getKey()+","+entry.getValue().toString());
			fw.write("\n");
		}
		fw.flush();
		fw.close();
		
	}
	
	
	
	private static long query(String input) throws IOException{
		long start = System.currentTimeMillis();
		SimpleResolver resolver = new SimpleResolver();
		if (!input.endsWith(".")){
			input = input + ".";
		}
		Name name = Name.fromString(input);
		Record query = Record.newRecord(name, Type.A, DClass.IN);
		Message msg = Message.newQuery(query);
		Message resp = resolver.send(msg);
		System.out.println(resp.toString());
		long end = System.currentTimeMillis();
		return (end-start);
	}
	
	
}
