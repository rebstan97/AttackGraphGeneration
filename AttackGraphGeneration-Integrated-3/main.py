from graph_generator import GraphGenerator
from input_parser import Parser
from notable_event.py import NotableEvent

parser = Parser()
startNodeSet = parser.parseStartNodes()

graphGenerator = GraphGenerator(startNodeSet)
DG = graphGenerator.generate_graph()

inputStateNode = input()
graphTraversal = GraphTraversal()
attackPath = graphTraversal.generate_attack_path(inputStateNode)