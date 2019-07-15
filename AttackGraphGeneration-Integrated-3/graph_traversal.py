from event import Event
from input_parser import Parser
from notable_event import NotableEvent

class GraphTraversal(object):

    def generate_attack_graph(self, stateNode):
        x = stateNode
        while (x != None):
            pair = parseNotableEvent(stateNode)
            attackPath.append(pair.first, pair.second)
            x = pair.second

        return attackPath

