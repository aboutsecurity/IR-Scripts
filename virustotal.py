# Checking suspicious files in a directory against Virustotal Database.

##############################
#                            #
# Ismael Valenzuela (c) 2013 #
#                            #
##############################


import requests,os,sys,hashlib,pprint

apikey = ''

def usage():
        print 'Usage: virustotal.py --mode <mode> --dir <directory>'
        print ''
        print 'Arguments:'
        print ''
        print ' --mode      Operating mode [report, behaviour]'
        print ''
        print ' --dir       Directory containing files to parse'
        print ''
        print ''

def md5(filename):
    """
    This function....
    """
    f=open(filename).read() # Read file at once (beware of memory exhaustion!)
    hash=hashlib.md5(f).hexdigest() # Calculate MD5 hash

    return hash

def behaviour_file(filename, resource):
    """
    This function ...
    """
    print "\nPulling BEHAVIOURAL REPORT from Virustotal for " + filename + " with hash " + resource + '\n'
    params = {'apikey': apikey, 'hash': resource}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/behaviour', params=params)
    json_response = response.json()

    pprint.pprint(json_response)

def report_file(filename, resource):
    """
    This function ...
    """
    print "\nPulling THE MOST RECENT REPORT from Virustotal for " + filename + " with hash " + resource + '\n'
    params = {'apikey': apikey, 'resource': resource}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response = response.json()

    pprint.pprint(json_response)

def main():

    if len(sys.argv)!= 5:
        usage()
        sys.exit(1)

    mode=sys.argv[2]
    path=sys.argv[4]

    if os.path.exists(path):
        listing=os.listdir(path)
    else:
        print "The directory \'" + path + "\' does not exist, exiting gracefully"
        sys.exit(1)

    for infile in listing:
        filename=os.path.join(path,infile) # Get full path
        if os.path.isdir(filename) == False: # If is not a directory entry
            try:
                filehash=md5(filename)

                if mode == 'report':
                    report_file(filename, filehash)
                elif mode == 'behaviour':
                    behaviour_file(filename, filehash)
                else:
                    print "Invalid mode specified"
                    usage()
                    sys.exit(1)


            except IOError:
                print "The file \'" + filename + "\' does not exist, exiting gracefully"
                sys.exit(1)


if __name__=='__main__':
  main()
