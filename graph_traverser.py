class GraphTraverser(object):
    def __init__(self, graph, eventSet, eventMapping):
        self.graph = graph
        self.eventSet = eventSet
        self.eventMapping = eventMapping
    
    def dfs(self, v, reverseList, order, dst, port, src=None):
        # print("dfs called")
        # print(v.to_string())
        # for i in self.graph.predecessors(v):
        #     print(i.to_string())

        if v.type == 'vuln' and v.entry:
            # reverseList.reverse()
            # print("Printing at node {}".format(v.to_string()))
            print(reverseList[::-1])

        for i in self.graph.predecessors(v):
            # print("Predecessor: {}".format(i.to_string()))
            if i.type == 'vuln':
                description = self.eventMapping[i.vulnerabilityName]
                event = self.eventSet.containsVulnEvent(description, dst, i.vulnerabilityPort, order)
                if event:
                    # print("Adding event: {}".format(event['DESCRIPTION']))
                    reverseList.append(description)
                    self.dfs(i, reverseList, event['ORDER'], event['DSTHOST'], event['PORT'], event['SRCHOST'])
                    reverseList.pop()
                    # print("Returned from state node")

            elif i.type == 'state':
                # Lateral movement to this state alr represented in vulnerability event
                if src == i.hostname:
                    self.dfs(i, reverseList, order, src, port)
                    # print("Returned from vuln node")
                event = self.eventSet.containsMovementEvent(i.hostname, dst, port, order)
                if event:
                    reverseList.append(event['DESCRIPTION'])
                    self.dfs(i, reverseList, event['ORDER'], event['SRCHOST'], event['PORT'])
                    reverseList.pop()
                    # print("Returned from vuln node")

    def start_traversal(self, order, dst, port, description, accessLevel):
        reverseList = []
        reverseList.append(description)
        notableEventNode = self.find_node(dst, accessLevel)
        eventSequence = self.dfs(notableEventNode, reverseList, order, dst, port)
    
    def find_node(self, dst, accessLevel):
        for i in self.graph.nodes:
            if i.type == 'state' and i.hostname == dst and i.accessLevel == accessLevel:
                return i
