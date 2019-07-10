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

        print("Enter start node(s) access level(s) >>>")
        accessLevels = input()
        if not accessLevels:
            print("Please enter a non-empty start node access level")
        startNodesAccessLevels = accessLevels.split(',')
        
        startNodeSet = []
        for i in range(0, numStartNodes):
            stateNode = StateNode(startNodesNames[i], startNodesAccessLevels[i])
            startNodeSet.append(stateNode)

        # Reject framework if start set is empty
        if not startNodeSet:
            print("Attack graph cannot have no start nodes")
            exit()

        return startNodeSet
    
    def parseVulnerability(self, stateNode):
        stateNodeName = stateNode.hostname
        vulnerabilitySet = []
        csv_file = csv.reader(open('test.csv', "rb"), delimiter=",")
        for row in csv_file:
            if stateNodeName == row[1]:
                vulnerabilityName = row[2]
                accessLevelGranted = row[3]
                vulnerabilityNode = VulnerabilityNode[vulnerabilityName, accessLevelGranted]
                vulnerabilitySet.append(vulnerabilityNode)
        return vulnerabilitySet
