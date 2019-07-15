from graph_generator import GraphGenerator
from input_parser import Parser

parser = Parser()
startNodeSet = parser.parseStartNodes()

graphGenerator = GraphGenerator(startNodeSet)
DG = graphGenerator.generate_graph()
