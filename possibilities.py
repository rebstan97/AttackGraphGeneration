import networkx as nx
from state_node import StateNode
from vulnerability_node import VulnerabilityNode

class Possibilities(object):

    def printPossiblePaths(self, DG, src, crownJewelSet):
        for dest in crownJewelSet:
            if DG.has_node(dest):
                paths = nx.all_simple_paths(DG, src, dest)
                if sum(1 for x in paths) == 0:
                    print("There are no possible paths from  notable event node (" + src.hostname + ", " + str(src.accessLevel) 
                            + ") to crown jewel (" + dest.hostname + ", " + str(dest.accessLevel) + ")")
                    return

                print("POSSIBLE PATHS TO REACH CROWN JEWEL " + dest.hostname + ":")
                paths = nx.all_simple_paths(DG, src, dest)
                pathCounter = 0
                for path in paths:
                    pathCounter = pathCounter + 1
                    print("Possible path " + str(pathCounter) + ":")
                    stepsCounter = 1
                    for node in path:
                        if type(node) is StateNode:
                            if node.hostname == src.hostname and node.accessLevel == src.accessLevel:
                                print(str(stepsCounter) + ") notable event at (" + node.hostname + ", " + str(node.accessLevel) + ")")
                                stepsCounter = stepsCounter + 1
                            else:
                                print("on node " + "(" + node.hostname + ", " + str(node.accessLevel) + ")")
                        elif type(node) is VulnerabilityNode:
                            print(str(stepsCounter) + ") exploit " + node.vulnerabilityName + " on port " + str(node.vulnerabilityPort), end = ' ')
                            stepsCounter = stepsCounter + 1

