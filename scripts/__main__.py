import sys
import argparse
from time import time
from utils import *
from corpus_builder import *
from distance_calculator import *
from data_flow_analyst import *
from csv_manager import *
from graph_builder import *


def main():
    # Set a recursion limit
    sys.setrecursionlimit(10000)

    timer_all = time()
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--working_dir', type=str, help="Dir to file containing nodes.csv/rels.csv/cpg_edges.csv/targets.csv.", default="WitcherD/working/tchecker-results/bWAPP")
    parser.add_argument('-o', '--out', type=str, help="Path to output file containing distance for each node.", default="WitcherD/working/instrument-info")

    args = parser.parse_args()

    # Read the target code locations
    csv_manager = CSVManager(args.working_dir)
    nodes_df, rels_df, cpg_edges_df, targets_df = csv_manager.read_csvs()
    target_nodes = map_targets_to_nodes(targets_df, nodes_df)

    timer_step = time()
    graph_builder = GraphBuilder(rels_df, nodes_df, cpg_edges_df, target_nodes)
    icfg, ast, whole_graph, added_cg_edges, instrumented_callee_nodes = graph_builder.build_icfg_ast_whole()

    distance_calculator = DistanceCalculator(target_nodes, icfg)
    dist = distance_calculator.calculate()
    if not dist and target_nodes:
        # The script may not have path-divergent nodes, due to phpjoern's limitation
        # so we use the whole graph to substitute the icfg and recalculate the distance
        icfg = whole_graph.copy()
        dist = distance_calculator.calculate()
    print(f"\nBlock distance calculation time (mins): {round((time() - timer_step) / 60, 2)}")

    timer_step = time()
    pdg = graph_builder.build_pdg()

    data_flow_analyst = DataFlowAnalyst(pdg, icfg, dist, ast, nodes_df)
    data_flow, data_flow_origins = data_flow_analyst.data_flow_backtrack(target_nodes)
    map_externals(nodes_df, data_flow_origins, args.out)

    nodes_to_instrument = {
        'dist': dist,
        'data_flow': data_flow
    }
    instrumented_files = csv_manager.save_to_csv(nodes_to_instrument, nodes_df, instrumented_callee_nodes, args.out)

    corpus_builder = CorpusBuilder(instrumented_files, data_flow, dist, ast, added_cg_edges, nodes_df, args.out)
    corpus_builder.extract_request_data()
    print(f"\nURL and inputs extraction time (mins): {round((time() - timer_step) / 60, 2)}")
    print(f"\nTotal time (mins): {round((time() - timer_all) / 60, 2)}")

if __name__ == '__main__':
    main()