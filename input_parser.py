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
        
        startNodeSet = []
        for i in range(0, numStartNodes):
            stateNode = StateNode(startNodesNames[i], 0)
            startNodeSet.append(stateNode)

        # Reject framework if start set is empty
        if not startNodeSet:
            print("Attack graph cannot have no start nodes")
            exit()

        return startNodeSet
    
    def parseVulnerabilities(self, host):
        # To be improved later because it is very inefficient
        vulnerabilitySet = []
        try:
            with open("vulnerabilities.csv") as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                for row in csv_reader:
                    if host == row[0]:
                        vulnerabilityName = row[4]
                        vulnerabilityPort = row[7].split("/")[0]
                        vulnerabilityNode = VulnerabilityNode(vulnerabilityName, vulnerabilityPort)
                        vulnerabilitySet.append(vulnerabilityNode)
            
            return vulnerabilitySet

        except IOError:
            print("File {} does not exist".format("vulnerabilities.csv"))
            exit()
