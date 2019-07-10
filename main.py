from graph_generator import GraphGenerator
from parser import Parser

parser = Parser()
startNodeSet = parser.parseStartNodes()

graphGenerator = GraphGenerator(startNodeSet)
DG = graph_generator.generate_graph()