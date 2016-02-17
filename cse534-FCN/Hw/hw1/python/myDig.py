import os
import sys
import dns.resolver
import dns.rdatatype
import dns.message
import dns.query
import dns.rcode

rootIndex = -1
rootsQueried = 0
ROUND_ROBIN_FILE = "./rrData.txt"
rootList = ['a.root-servers.net', 'b.root-servers.net', 'c.root-servers.net', 'd.root-servers.net', 'e.root-servers.net',
            'f.root-servers.net', 'g.root-servers.net', 'h.root-servers.net', 'i.root-servers.net', 'j.root-servers.net',
            'k.root-servers.net', 'l.root-servers.net', 'm.root-servers.net']

def run(domain, type):
    global rootIndex
    global rootsQueried
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

    response = queryAllRoots(input, type)
    if not response:
        print 'ERROR: Could not obtain the ip address of input'
    try:
        f = open(ROUND_ROBIN_FILE, 'w+')
        f.write(str(rootIndex))
        f.write('\n')
        f.write('Last used root: '+rootList[rootIndex])
        f.flush()
        f.close()
    except:
        print "ERROR occurred while updating round robin file"


def queryAllRoots(input, type):
    response = False
    global rootsQueried
    while not response and rootsQueried < len(rootList):
        global rootIndex
        rootIndex = (rootIndex +1)%13
        root = rootList[rootIndex]
        response = getFinalAddress(root, input, type)
        rootsQueried += 1
    return response

def getFinalAddress(address, domain, type):
    simpleResolver = dns.resolver.get_default_resolver()
    soln = []
    address = simpleResolver.query(address).rrset[0].to_text()
    #try:
    while True:
        query = dns.message.make_query(domain, type)
        response = dns.query.udp(query, address)
        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                print ('%s does not exist.' % domain)
                sys.exit(0)
            else:
                return False
        authoritySection = response.authority
        answerSection = response.answer
        if len(answerSection) > 0 and answerSection[0].rdtype == dns.rdatatype.A:
            soln = answerSection
            break
        elif len(answerSection) > 0 and answerSection[0].rdtype == dns.rdatatype.CNAME:
            domain = answerSection[0][0].target
        elif len(authoritySection) > 0 and authoritySection[0].rdtype == dns.rdatatype.NS:
            address = authoritySection[0][0].target
            address = simpleResolver.query(address).rrset[0].to_text()
        else:
            break
    if len(soln) > 0:
        #print answerSection[0].to_text()
        print response.to_text()
        return True
    else:
        return False
    #except:
    #    return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print 'Please enter the domain to query and type of query'
    else:
        #run(sys.argv[1], sys.argv[2])
        run('www.google.com', 'A')