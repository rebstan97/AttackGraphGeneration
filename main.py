from event_set import EventSet
from graph_generator import GraphGenerator
from graph_traverser import GraphTraverser
from input_parser import Parser
# import graph_storage as gs

parser = Parser()
startNodeSet = parser.parseStartNodes()
vulnDict, portDict = parser.parseVulnerabilities()
eventMapping = parser.parseEventMapping()
eventSet = EventSet()

# Generate attack graph
graphGenerator = GraphGenerator(startNodeSet, vulnDict, portDict)
DG = graphGenerator.generate_graph()

order, src, port, description, accessLevel = parser.parseNotableEvent()

graphTraverser = GraphTraverser(DG, eventSet, eventMapping)
eventSequence = graphTraverser.start_traversal(order, src, port, description, accessLevel)