# Generates an attack graph of state nodes and vulnerability nodes 

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
                    DG.add_node(vulnerabilityNode)
                    DG.add_edge(vulnerabilityNode, startNode)

        stateNodeSet = self.startNodeSet

        # iterate through each state node's reachable node set
        for stateNode in stateNodeSet:
            host = stateNode.hostname
            currAccessLevel = stateNode.accesslevel
            reachableSet = self.get_reachable(host)
            
            # reachable is a tuple (hostname, port)
            for reachable in reachableSet:
                vulnerablitySet = self.get_vulnerabilities(reachable[0])

                # add each vulnerability node as the state node's child node if:
                # 1) sufficient privilege level
                # 2) reachable to port associated with that vulnerability
                for vulnerabilityNode in vulnerablitySet:
                    newStateNodes = []
                    if currAccessLevel >= vulnerabilityNode.requiredPrivilege and vulnerabilityNode.vulnerabilityPort == reachable[1]:
                        DG.add_node(vulnerabilityNode)  
                        DG.add_edge(stateNode, vulnerabilityNode)
                        
                        # compare gained access level from this vulnerability with preceeding access level
                        # and add vulnerable node as the vulnerability node's child node
                        newAccessLevel = self.get_access_granted(reachableNode, vulnerabilityNode.accessLevel, currAccessLevel)
                        vulnerableNode = StateNode(reachableNode[0], newAccessLevel)
                        DG.add_node(vulnerableNode)
                        DG.add_edge(vulnerabilityNode, vulnerableNode)
                        newStateNodes.append(vulnerableNode)

            stateNodeSet = newStateNodes

        return DG