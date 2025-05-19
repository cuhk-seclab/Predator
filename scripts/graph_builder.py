import networkx as nx

class GraphBuilder:
    def __init__(self, rels_df, nodes_df, cpg_edges_df, target_nodes):
        self.rels_df = rels_df
        self.nodes_df = nodes_df
        self.cpg_edges_df = cpg_edges_df
        self.target_nodes = target_nodes
        self.icfg = nx.DiGraph()
        self.whole_graph = nx.DiGraph()
        self.ast = nx.DiGraph()
        self.added_cg_edges = {}
        self.instrumented_callee_nodes = []

    def backward_traverse(self, graph, start_node, flag, visited=None):
        if visited is None:
            visited = set()
        if start_node in graph.nodes and flag or start_node in visited:
            return
        visited.add(start_node)
        related_edges = self.rels_df[self.rels_df['end'] == start_node]
        predecessors = related_edges['start'].tolist()
        graph.add_edges_from([(predecessor, start_node) for predecessor in predecessors])
        
        for predecessor in predecessors:
            self.backward_traverse(graph, predecessor, True, visited)

    def forward_traverse(self, graph, end_node, flag, visited=None):
        if visited is None:
            visited = set()
        if end_node in graph.nodes and flag or end_node in visited:
            return
        visited.add(end_node)
        related_edges = self.rels_df[self.rels_df['start'] == end_node]
        successors = related_edges['end'].tolist()
        graph.add_edges_from([(end_node, successor) for successor in successors])

        for successor in successors:
            self.forward_traverse(graph, successor, True, visited)

    def build_icfg_ast_whole(self):
        print("Building AST...")
        cfg_df = self.cpg_edges_df[self.cpg_edges_df['type'] == 'FLOWS_TO']
        cg_df = self.cpg_edges_df[self.cpg_edges_df['type'] == 'CALLS']
        all_len = len(cg_df)
        round_num = 1

        cfg_edges = list(cfg_df.iterrows())
        self.icfg.add_edges_from([(row['start'], row['end'], {'label': 'CFG'}) for _, row in cfg_edges])
        cg_edges = list(cg_df.iterrows())
        rel_edges = list(self.rels_df.iterrows())
        self.whole_graph.add_edges_from([(row['start'], row['end'], {'label': 'REL'}) for _, row in rel_edges])
        self.ast = self.whole_graph.copy()
        self.whole_graph.add_edges_from([(row['start'], row['end'], {'label': 'CFG'}) for _, row in cfg_edges])
        self.whole_graph.add_edges_from([(row['start'], row['end'], {'label': 'CG'}) for _, row in cg_edges])
        print("Building iCFG...")
        for _, row in cg_edges:
            for target in self.target_nodes:
                if nx.has_path(self.whole_graph, row['end'] + 1, target):
                    self.icfg.add_edges_from([(row['start'], row['end'], {'label': 'CG'})])
                    self.icfg.add_edges_from([(row['end'], row['end'] + 1, {'label': 'CG'})])
                    self.icfg.add_edges_from([(row['start'], row['end'] + 2, {'label': 'CG'})])
                    first_node = self.nodes_df[self.nodes_df['id:int'] ==  row['end'] + 3].iloc[0]
                    while first_node['type'] != 'AST_STMT_LIST':
                        first_node = self.nodes_df[self.nodes_df['id:int'] == first_node['id:int'] + 1].iloc[0]
                    first_node = self.nodes_df[self.nodes_df['id:int'] == first_node['id:int'] + 1].iloc[0]
                    self.instrumented_callee_nodes.append(first_node['id:int'])
                    if first_node['id:int'] in self.icfg.nodes:
                        has_reachable = False
                        has_unreachable = False
                        for succ in list(self.icfg.successors(first_node['id:int'])):
                            if nx.has_path(self.whole_graph, succ, target):
                                has_reachable = True
                            else:
                                has_unreachable = True
                        if has_reachable and has_unreachable:
                            pass
                        elif has_unreachable:
                            self.icfg.add_edges_from([(first_node['id:int'], row['end'] + 1, {'label': 'CG'})])
                        elif has_reachable:
                            self.icfg.add_edges_from([(first_node['id:int'], row['end'] + 2, {'label': 'CG'})])
                        else:
                            self.icfg.add_edges_from([(first_node['id:int'], row['end'] + 1, {'label': 'CG'})])
                            self.icfg.add_edges_from([(first_node['id:int'], row['end'] + 2, {'label': 'CG'})])
                    else:
                        self.icfg.add_edges_from([(first_node['id:int'], row['end'] + 1, {'label': 'CG'})])
                        self.icfg.add_edges_from([(first_node['id:int'], row['end'] + 2, {'label': 'CG'})])
                    self.added_cg_edges[first_node['id:int']] = row['start']
                    predecessors = list(self.icfg.predecessors(row['start']))
                    if predecessors == []:
                        self.backward_traverse(self.icfg, row['start'], False)
                    break
            print(f"iCFG build progress: {round_num} / {all_len}", end="\r")
            round_num += 1

        for target in self.target_nodes:
            self.backward_traverse(self.icfg, target, False)
        return self.icfg, self.ast, self.whole_graph, self.added_cg_edges, self.instrumented_callee_nodes

    def build_pdg(self):
        print("Building PDG...")
        pdg = self.icfg.copy()
        round_num = 1
        pdg_df = self.cpg_edges_df[self.cpg_edges_df['type'] == 'REACHES']
        pdg_edges = list(pdg_df.iterrows())
        pdg.add_edges_from([(row['start'], row['end'], {'label': row['var']}) for _, row in pdg_edges])
        cg_df = self.cpg_edges_df[self.cpg_edges_df['type'] == 'CALLS']
        cg_edges = list(cg_df.iterrows())
        all_len = len(self.target_nodes) + len(cg_edges)
        for _, row in cg_edges:
            if (row['start'], row['end']) in pdg.edges:
                self.backward_traverse(pdg, row['start'], False)
                self.forward_traverse(pdg, row['end'], False)
            print(f"pdg build progress: {round_num} / {all_len}", end="\r")
            round_num += 1

        for target in self.target_nodes:
            print(f"pdg build progress: {round_num} / {all_len}", end="\r")
            self.backward_traverse(pdg, target, False)
            round_num += 1

        return pdg
