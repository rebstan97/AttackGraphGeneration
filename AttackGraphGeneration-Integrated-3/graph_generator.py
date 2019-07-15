# Generates an attack graph of state nodes and vulnerability nodes 

import matplotlib.pyplot as plt
import networkx as nx
from input_parser import Parser
from reachable import Reachable
from state_node import StateNode

class GraphGenerator(object):

    def __init__(self, startNodeSet):
        self.startNodeSet = startNodeSet
    
    # needs to link with network topology 
    def get_reachable(self, hostname):
        getReachable = Reachable()
        reachableSet = getReachable.get_reachable(hostname)
        return reachableSet
    
    def get_vulnerabilities(self, reachableNode):
        parser = Parser()
        vulnerabilitySet = parser.parseVulnerabilities(reachableNode)
        return vulnerabilitySet

    def get_access_granted(self, reachableNode, gainedAccessLevel, currAccessLevel):
        if currAccessLevel < gainedAccessLevel:
            return gainedAccessLevel
        
        return currAccessLevel

    def generate_graph(self):
        DG = nx.DiGraph()

        # add vulnerabilities for start nodes
        for startNode in self.startNodeSet:
            vulnerablitySet = self.get_vulnerabilities(startNode.hostname)
            for vulnerabilityNode in vulnerablitySet:
                if vulnerabilityNode.requiredPrivilege == 0:
                    startNode.accessLevel = vulnerabilityNode.get_gained_access()
                    DG.add_edge(vulnerabilityNode, startNode)
                    print("Added edge from {} to {}".format(vulnerabilityNode.to_string(), startNode.to_string()))
        stateNodeSet = self.startNodeSet
        newStateNodes = set()

        while stateNodeSet:
            # iterate through each state node's reachable node set
            for index, stateNode in enumerate(stateNodeSet):

                print("State node: {}".format(stateNode.to_string()))

                host = stateNode.hostname
                currAccessLevel = stateNode.accessLevel
                reachableSet = self.get_reachable(host)
                
                # reachable is a tuple (hostname, port)
                for reachable in reachableSet:
                    vulnerablitySet = self.get_vulnerabilities(reachable[0])

                    # add each vulnerability node as the state node's child node if:
                    # 1) sufficient privilege level
                    # 2) reachable to port associated with that vulnerability
                    for vulnerabilityNode in vulnerablitySet:
                        # print("Reachable node {} has vulnerability {}".format(reachable, vulnerabilityNode.to_string()))
                        if currAccessLevel >= vulnerabilityNode.requiredPrivilege and vulnerabilityNode.vulnerabilityPort == reachable[1]: 
                            if not DG.has_edge(vulnerabilityNode, stateNode):
                                # print("No edge from {} to {}".format(vulnerabilityNode.to_string(), stateNode.to_string()))
                                DG.add_edge(stateNode, vulnerabilityNode)
                                print("Added edge from {} to {}".format(stateNode.to_string(), vulnerabilityNode.to_string()))
                            
                            # compare gained access level from this vulnerability with preceeding access level
                            # and add vulnerable node as the vulnerability node's child node
                            newAccessLevel = self.get_access_granted(reachable, vulnerabilityNode.accessLevel, currAccessLevel)
                            vulnerableNode = StateNode(reachable[0], newAccessLevel)
                            if not DG.has_node(vulnerableNode):
                                newStateNodes.add(vulnerableNode)
                                print("Adding {} to newStateNodes".format(vulnerableNode.to_string()))
                            DG.add_edge(vulnerabilityNode, vulnerableNode)
                            print("Added edge from {} to {}".format(vulnerabilityNode.to_string(), vulnerableNode.to_string()))

                if index == len(stateNodeSet) - 1:
                    stateNodeSet = newStateNodes
                    newStateNodes = set()

        # pos = nx.spring_layout(DG)
        # nx.draw_networkx_nodes(DG, pos)
        # nx.draw_networkx_edges(DG, pos)
        # plt.show()
        return DG