# Parse the start nodes
# - Returns a list of start nodes 
# Parse the name of the node
# - Returns a list of vulnerabilities of the specific node 

import csv
from state_node import StateNode
from vulnerability_node import VulnerabilityNode

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

        print("Enter start node(s) name(s) >>>")
        names = input()
        if not names:
            print("Please enter a non-empty start node name")
        startNodesNames = names.split(',')
        
        startNodeSet = set()
        for i in range(0, numStartNodes):
            stateNode = StateNode(startNodesNames[i], 0)
            startNodeSet.add(stateNode)

        # Reject framework if start set is empty
        if not startNodeSet:
            print("Attack graph cannot have no start nodes")
            exit()

        return startNodeSet
 
    # create 2 dictionaries:
    # 1) mapping of (vulnName, vulnPort) to VulnerabilityNode
    # 2) mapping of vulnName to vulnPort
    def parseVulnerabilities(self):       
        try:
            with open("vulnerabilities.csv") as csv_file:
                next(csv_file, None) # Skip first row (header)
                csv_reader = csv.reader(csv_file, delimiter=',')

                vulnDict = {}
                portDict = {}
                for row in csv_reader:
                    hostname = row[0]
                    vulnName = row[4]
                    vulnPort = int(row[7].split("/")[0])
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
            print("File {} does not exist".format("vulnerabilities.csv"))
            exit() 

