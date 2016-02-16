import os
import dns.resolver
import dns.rdatatype
import dns.message
import dns.query
import dns.rcode

rootIndex = -1
rootsQueried = 0
ROUND_ROBIN_FILE = "./rrData.txt"

def run(domain):
    if os.path.isfile(ROUND_ROBIN_FILE):
        try:
            f = open(ROUND_ROBIN_FILE)
            rootIndex = int(f.readline().strip())
        except:
            print 'Error occurred while reading file'
            return
    else:
        rootIndex = 0

    rootsQueried = 0

    input = domain
    if input[-1] != '.':
        input += '.'

    dots = len(input) - len(input.replace('.', ''))
    # Record[] records = queryAllRoots(input, dots);
    # ArrayList<String> results = getResults(records);
    #
    # if(results.size() == 0){
    #     System.out.println("ERROR: Could not obtain the ip address of input");
    # }
    # else{
    #     for(String s : results){
    #         System.out.println(s.split("/")[1]);
    #     }
    # }
    #
    # try{
    #     updateFile(f);
    # }
    # catch(Exception e){
    #     System.out.println("File root index update failed");
    #     return;
    # }

# def Record[] queryAllRoots(input, dots):
#     root;
#     Record[] records = null;
#     while((records == null || records.length == 0)&& rootsQueried < rootList.size()):
#         rootIndex = (rootIndex +1)%13;
#         root = rootList.get(rootIndex);
#         records = getFinalAddress(root, input, dots);
#         rootsQueried++;
#         //System.out.println("Query number: "+rootsQueried);
#         //System.out.println("Query index: "+rootIndex);
#     return records;

def getFinalAddress(address, domain, dots):
        default = dns.resolver.get_default_resolver()
        address = default.query(address).rrset[0].to_text()
    #try:
        while dots > 0:
            resolver = dns.resolver.Resolver()
            resolver.nameservers  =  ['202.12.27.33']
            query = dns.message.make_query(domain, dns.rdatatype.A)
            response = dns.query.udp(query, address)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    raise Exception('%s does not exist.' % domain)
                else:
                    raise Exception('Error %s' % dns.rcode.to_text(rcode))

            rrset = None
            if len(response.authority) > 0 and dots > 1:
                rrset = response.authority[0]
            else:
                rrset = response.answer[0]

            rr = rrset[0]
            if rr.rdtype == dns.rdatatype.SOA:
                print 'Same server is authoritative for %s' % domain
            else:
                authority = rr.target
                address = default.query(authority).rrset[0].to_text()
                print '%s is authoritative for %s' % (authority, domain)
                #nameserver = default.query(authority).rrset[0].to_text()
            dots -= 1
            #depth += 1
            #if dots > 1:
             #   print "in if"
               #records = resp.getSectionArray(Section.AUTHORITY);
               # address = ((NSRecord) records[2]).getAdditionalName().toString();
            #dots -= 1

        #records = resp.getSectionArray(Section.ANSWER);
        #return records;
    #except:
        print "ERROR"
        #return [];


getFinalAddress("a.root-servers.net", "www.facebook.com", 3)