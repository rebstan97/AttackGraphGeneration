from state_node import StateNode
from vulnerability_node import VulnerabilityNode
import csv
import os

class Parser(object):

    def parseStartNodes(self):
        while True:
            try: 
                numStartNodes = int(input("Enter number of start nodes in attack graph: >>>"))
                if numStartNodes > 0:
                    break
                print("Please enter a positive integer")
            except ValueError:
                print("Please enter a positive integer")
        
        while True:
            print("Enter start node(s) name(s), separated by comma >>>")
            names = input()
            if names:
                startNodesNames = names.split(',')
                if len(startNodesNames) == numStartNodes:
                    break
                else:
                    print("Number of start node(s) must be as specified")
                    continue
            print("Please enter a non-empty start node name")
        
        startNodeSet = set()
        for i in range(0, numStartNodes):
            stateNode = StateNode(startNodesNames[i], 0)
            startNodeSet.add(stateNode)

        # Reject framework if start set is empty
        if not startNodeSet:
            print("Attack graph cannot have no start nodes")
            exit()

        return startNodeSet

    def parseNotableEvent(self):
        while True:
            print("Enter notable event >>>")
            event = input()
            if event:
                eventComponents = event.split(",")
                if len(eventComponents) == 8:
                    break
                else:
                    print("Please enter a valid notable event")
                    continue
            print("Please enter a non-empty notable event")

        while True:
            try: 
                accessLevel = int(input("Enter access level of attacker >>>"))
                if accessLevel >= 0 and accessLevel <= 2:
                    break
                print("Please enter 0 (no access), 1 (user) or 2 (root)")
            except ValueError:
                print("Please enter 0 (no access), 1 (user) or 2 (root)")
        
        timestamp = int(eventComponents[0])
        src = eventComponents[1]
        dst = eventComponents[2]
        port = int(eventComponents[6])
        description = eventComponents[7]

        return timestamp, src, dst, port, description, accessLevel

    def parseReachability(self):
        file_input = input("Enter CSV file (including extension) containing reachability graph: ")
        filename = file_input.split("/")[-1]
        directory = file_input.replace(filename, '')

        if directory:
            curr_dir = os.getcwd()
            os.chdir(directory)

        try:
            with open(filename) as csv_file:
                os.chdir(curr_dir)
                csv_reader = csv.reader(csv_file, delimiter=',')
                reachability_dict = {}
                for row in csv_reader:
                    hostname = row[0]
                    reachable = row[1:]
                
                    reachable_set = set()
                    for i in reachable:
                        neighbour = i.split(",")[0]
                        if not neighbour:
                            continue
                        port = int(i.split(",")[1])
                        reachable_set.add((neighbour, port))

                    reachability_dict[hostname] = reachable_set

                return reachability_dict

        except IOError:
            print("File {} does not exist".format(filename))
            exit()
 
    # Creates 2 dictionaries:
    # 1) Mapping of (vulnName, vulnPort) to VulnerabilityNode
    # 2) Mapping of vulnName to vulnPort
    def parseVulnerabilities(self):
        file_input = input("Enter CSV file (including extension) containing vulnerabilities: ")
        filename = file_input.split("/")[-1]
        directory = file_input.replace(filename, '')

        if directory:
            curr_dir = os.getcwd()
            os.chdir(directory)

        try:
            with open(filename) as csv_file:
                os.chdir(curr_dir)
                next(csv_file, None) # Skip first row (header)
                csv_reader = csv.reader(csv_file, delimiter=',')

                vulnDict = {}
                portDict = {}
                for row in csv_reader:
                    hostname = row[0]
                    vulnName = row[1]
                    vulnPort = int(row[2].split("/")[0])
                    vulnNode = VulnerabilityNode(vulnName, vulnPort)

                    if (hostname, vulnPort) in vulnDict:
                        vulnDict[(hostname, vulnPort)].add(vulnDict)
                    else:
                        vulnSet = set()
                        vulnSet.add(VulnerabilityNode(vulnName, vulnPort))
                        vulnDict[(hostname, vulnPort)] = vulnSet

                    if hostname in portDict:
                        portDict[hostname].add(vulnPort)
                    else:
                        portSet = set()
                        portSet.add(vulnPort)                    
                        portDict[hostname] = portSet
          
            return vulnDict, portDict

        except IOError:
            print("File {} does not exist".format(filename))
            exit() 

    # Creates a dictionary mapping of CVE to event description 
    # For simplicity, assumes each CVE is mapped to a single event
    # Use "cveToEvent.csv" as a sample
    def parseEventMapping(self):
        cveToEventDict = {}
        file_input = input("Enter CSV file (including extension) containing mapping of CVE to event: ")
        filename = file_input.split("/")[-1]
        directory = file_input.replace(filename, '')

        if directory:
            curr_dir = os.getcwd()
            os.chdir(directory)

        try:
            with open(filename) as csv_file:
                os.chdir(curr_dir)
                next(csv_file, None) # Skip first row (header)
                csv_reader = csv.reader(csv_file, delimiter=',')
                for row in csv_reader:
                    cve = row[0]
                    eventDescription = row[1]
                    # if cve in cveToEventDict:
                    #     cveToEventDict[cve].add(eventDescription)
                    # else:
                    # eventSet = set()
                    # eventSet.add(eventDescription)                    
                    # cveToEventDict[cve] = eventSet
                    cveToEventDict[cve] = eventDescription 
            return cveToEventDict

        except IOError:
            print("File {} does not exist".format(filename))
            exit() 

    def parseCrownJewels(self):
       while True:
           try:
               numCrownJewels = int(input("Enter number of crown jewels in attack graph: >>>"))
               if numCrownJewels > 0:
                   break
               print("Please enter a positive integer")
           except ValueError:
               print("Please enter a positive integer")

       print("Enter crown jewel(s) name(s) >>>")
       names = input()
       if not names:
           print("Please enter a non-empty crown jewel name")
       crownJewelNames = names.split(',')
      
       crownJewelSet = set()
       for i in range(0, numCrownJewels):
           for j in range(3):
               crownJewel = StateNode(crownJewelNames[i], j)
               crownJewelSet.add(crownJewel)

       # Reject if crown jewels do not exist
       # not implemented yet
       # currently, assume that crown jewels entered by user must exist

       # Reject if crown jewel set is empty
       if not crownJewelSet:
           print("Attack graph cannot have no crown jewels")
           exit()

       return crownJewelSet

