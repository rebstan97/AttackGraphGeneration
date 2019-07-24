class GraphTraverser(object):
    def __init__(self, graph, eventSet, eventMapping, networkNodes):
        self.graph = graph
        self.eventSet = eventSet
        self.eventMapping = eventMapping
        self.networkNodes = networkNodes
    
    def dfs(self, v, reverseList, timestamp, dst, port, src=None):
        # print("dfs called")
        # print(v.to_string())
        # for i in self.graph.predecessors(v):
        #     print(i.to_string())

        if v.type == 'vuln' and v.entry and src not in self.networkNodes:
            # reverseList.reverse()
            # print("Printing at node {}".format(v.to_string()))
            print('')
            return self.print_path(reverseList[::-1])

        for i in self.graph.predecessors(v):
            # print("Predecessor: {}".format(i.to_string()))
            if i.type == 'vuln':
                description = self.eventMapping[i.vulnerabilityName]
                event = self.eventSet.containsVulnEvent(description, dst, i.vulnerabilityPort, timestamp)
                if event:
                    event_string = event['TIMESTAMP'] + ', ' + event['SRCHOST'] + ', ' + event['DSTHOST'] + ', ' + description
                    # print("Adding event: {}".format(event_string))
                    reverseList.append(event_string)
                    self.dfs(i, reverseList, event['TIMESTAMP'], event['DSTHOST'], event['DSTPORT'], event['SRCHOST'])
                    reverseList.pop()
                    # print("Returned from state node")

            elif i.type == 'state':
                if src == i.hostname:
                    self.dfs(i, reverseList, timestamp, src, port)
                    # print("Returned from vuln node")
                # Adversary made use of trust relationship for lateral movement
                elif src == dst:
                    event = self.eventSet.containsMovementEvent(i.hostname, dst, port, timestamp)
                    if event:
                        event_string = event['TIMESTAMP'] + ', ' + event['SRCHOST'] + ', ' + event['DSTHOST'] + ', ' + event['DESCRIPTION']
                        reverseList.append(event_string)
                        self.dfs(i, reverseList, event['TIMESTAMP'], event['SRCHOST'], event['DSTPORT'])
                        reverseList.pop()
                        # print("Returned from vuln node")

    def start_traversal(self, timestamp, src, dst, port, description, accessLevel):
        reverseList = []
        reverseList.append('Notable event: ' + str(timestamp) + ', ' + src + ', '+ dst + ', ' + description)
        notableEventNode = self.find_node(src, accessLevel)
        eventSequence = self.dfs(notableEventNode, reverseList, timestamp, src, port)
    
    def find_node(self, dst, accessLevel):
        for i in self.graph.nodes:
            if i.type == 'state' and i.hostname == dst and i.accessLevel == accessLevel:
                return i

    def print_path(self, list):
        print("Entry: {}".format(list[0]))
        for i in list[1:]:
            print(' -> ' + i)