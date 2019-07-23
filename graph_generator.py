# Generates an attack graph of state nodes and vulnerability nodes 

import networkx as nx
from input_parser import Parser
from state_node import StateNode

class GraphGenerator(object):

    def __init__(self, startNodeSet, adjList, vulnDict, portDict):
        self.startNodeSet = startNodeSet
        self.adjList = adjList
        self.vulnDict = vulnDict
        self.portDict = portDict
    
    # needs to link with network topology 
    def get_reachable(self, hostname):
        reachableSet = self.adjList[hostname]
        return reachableSet

    def get_vulnerabilities(self, host, port):
        if (host, port) not in self.vulnDict:
            return None
        return self.vulnDict[(host, port)]

    def get_access_granted(self, vulnerabilityNode, currAccessLevel):
        if vulnerabilityNode.accessVector == 'Network':
            return vulnerabilityNode.accessLevel
        elif vulnerabilityNode.accessVector == 'Local':
            if currAccessLevel < vulnerabilityNode.accessLevel:
                return vulnerabilityNode.accessLevel
            else:
                return currAccessLevel

    def generate_graph(self):
        DG = nx.DiGraph()

        # add vulnerabilities for start nodes
        for startNode in self.startNodeSet:
            startNodePorts = self.portDict[startNode.hostname]
            for port in startNodePorts:
                vulnerabilitySet = self.get_vulnerabilities(startNode.hostname, port)
                if not vulnerabilitySet:
                    continue
                for vulnerabilityNode in vulnerabilitySet:
                    vulnerabilityNode.entry = True
                    if vulnerabilityNode.requiredPrivilege == 0:
                        startNode.accessLevel = vulnerabilityNode.accessLevel
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
                    # print("Host {} is reachable to host {}, port {}".format(host, reachable[0], reachable[1]))
                    vulnerablitySet = self.get_vulnerabilities(reachable[0], reachable[1])

                    if not vulnerablitySet: # No vulnerabilities associated
                        continue 

                    # add each vulnerability node as the state node's child node if:
                    # 1) sufficient privilege level
                    # 2) reachable to port associated with that vulnerability
                    for vulnerabilityNode in vulnerablitySet:
                        # print("Reachable node {} has vulnerability {}".format(reachable, vulnerabilityNode.to_string()))
                        if (currAccessLevel >= vulnerabilityNode.requiredPrivilege) and not (vulnerabilityNode.accessVector == 'Local' and not host == reachable[0]): 
                            if not DG.has_edge(vulnerabilityNode, stateNode) and not DG.has_edge(stateNode, vulnerabilityNode):
                                # print("No edge from {} to {}".format(vulnerabilityNode.to_string(), stateNode.to_string()))
                                DG.add_edge(stateNode, vulnerabilityNode)
                                print("Added edge from {} to {}".format(stateNode.to_string(), vulnerabilityNode.to_string()))
                            
                            newAccessLevel = self.get_access_granted(vulnerabilityNode, currAccessLevel)
                            vulnerableNode = StateNode(reachable[0], newAccessLevel)
                            if not DG.has_node(vulnerableNode):
                                newStateNodes.add(vulnerableNode)
                                print("Adding {} to newStateNodes".format(vulnerableNode.to_string()))
                            if not DG.has_edge(vulnerabilityNode, vulnerableNode):
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