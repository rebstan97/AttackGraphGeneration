# Generates an unsimplified attack graph of state nodes and vulnerability nodes 

import networkx as nx
from state_node import StateNode
from parser import Parser
from get_reachable import GetReachable

class GraphGenerator(object):

    def __init__(self, startNodeSet):
        self.startNodeSet = startNodeSet
    
    # needs to link with network topology 
    def get_reachable(self, stateNode):
        getReachable = GetReachable()
        reachableSet = getReachable.reachability(stateNode)
        return reachableSet
    
    def get_vulnerabilities(self, reachableNode):
        parser = Parser()
        vulnerabilitySet = parser.parseVulnerability(reachableNode)
        return vulnerabilitySet

    def access_granted(self, reachableNode, gainedAccessLevel, highestAccessLevel):
        if highestAccessLevel < gainedAccessLevel:
            highestAccessLevel = gainedAccessLevel
        vulnerableNode = StateNode(reachableNode.hostname, highestAccessLevel)
        return vulnerableNode

    def generate_graph(self):
        DG = nx.DiGraph()

        # iterate through each state node's reachable node
        for stateNode in self.startNodeSet:
            highestAccessLevel = stateNode.accesslevel
            reachableSet = self.get_reachable(stateNode)
            
            # get each reachable node's vulnerabilities
            for reachableNode in reachableSet:
                vulnerablitySet = self.get_vulnerabilities(reachableNode):

                # add each vulnerability node as the state node's child node
                for vulnerabilityNode in vulnerablitySet:
                    DG.add_node(vulnerabilityNode)  
                    DG.add_edge(stateNode, vulnerabilityNode)
                    
                    # compare gained access level from this vulnerability with preceeding access level
                    # and add vulnerable node as the vulnerability node's child node
                    vulnerableNode = self.access_granted(reachableNode, vulnerabilityNode.accesslevel, highestAccessLevel)
                    DG.add_node(vulnerableNode)
                    DG.add_edge(vulnerabilityNode, vulnerableNode)
        return DG