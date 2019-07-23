from event_finder import EventFinder
from graph_generator import GraphGenerator
from graph_traverser import GraphTraverser
from input_parser import Parser

parser = Parser()
startNodeSet = parser.parseStartNodes()
adjList = parser.parseReachability()
vulnDict, portDict = parser.parseVulnerabilities()
eventMapping = parser.parseEventMapping()
eventSet = EventFinder()

# Generate attack graph
graphGenerator = GraphGenerator(startNodeSet, adjList, vulnDict, portDict)
DG = graphGenerator.generate_graph()

timestamp, src, dst, port, description, accessLevel = parser.parseNotableEvent()

graphTraverser = GraphTraverser(DG, eventSet, eventMapping, portDict.keys())
eventSequence = graphTraverser.start_traversal(timestamp, src, dst, port, description, accessLevel)