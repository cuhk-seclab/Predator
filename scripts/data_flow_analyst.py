import networkx as nx

class DataFlowAnalyst:
    def __init__(self, pdg, icfg, dist, ast, nodes_df):
        self.nodes_df = nodes_df
        self.pdg = pdg
        self.icfg = icfg
        self.dist = dist
        self.ast = ast
        self.data_flow_nodes = {}
        self.data_flow_origins = {}
        self.pdg_edge_labels = nx.get_edge_attributes(pdg, 'label')

    def ast_visitor(self, node_id):
        current_node = self.nodes_df[self.nodes_df['id:int'] == node_id]
        if current_node.empty:
            return None
        current_code = current_node.iloc[0]['code']
        if current_code in ['_POST', '_GET', '_REQUEST', '_COOKIE']:
            key_node_id = current_node.iloc[0]['id:int'] + 1
            key_node = self.nodes_df[self.nodes_df['id:int'] == key_node_id]
            if not key_node.empty:
                key_code = key_node.iloc[0]['code']
                return key_code

        for child_id in self.ast.successors(node_id):
            result = self.ast_visitor(child_id)
            if result is not None:
                return result  

        return None  

    def data_flow_backward_traverse(self, start_node, visited=None, current_data_flow_path=[]):
        if visited is None:
            visited = set()
        visited.add(start_node)
        
        predecessors = list(self.pdg.predecessors(start_node))
        for predecessor in predecessors:
            if self.pdg_edge_labels.get((predecessor, start_node)) != None and self.pdg_edge_labels[(predecessor, start_node)] not in ['CG', 'CFG', 'REL', '_REQUEST', '_COOKIE', '_GET', '_POST', '_SERVER', '_FILES', '_SESSION', '_ENV', '_SERVER']:
                self.data_flow_nodes[predecessor] = str(self.pdg_edge_labels[(predecessor, start_node)])
                if current_data_flow_path != []:
                    current_data_flow_path.append(predecessor)
            if predecessor not in visited:
                if self.pdg_edge_labels.get((predecessor, start_node)) in ['CG', 'CFG'] and self.icfg.out_degree(predecessor) >= 2 and self.dist.get(predecessor) == None:
                    continue
                self.data_flow_backward_traverse(predecessor, visited, current_data_flow_path)
        
        if len(current_data_flow_path) >= 2:
            data_flow_leaf = current_data_flow_path[0]
            data_flow_root = current_data_flow_path[-1]
            if data_flow_leaf == data_flow_root:
                return
            
            # check if any global dict key exists in the root node
            global_key = self.ast_visitor(data_flow_root)
            if global_key != None:
                self.data_flow_nodes[data_flow_root] = str(global_key)

            if self.data_flow_origins.get(data_flow_leaf) == None:
                self.data_flow_origins[data_flow_leaf] = [data_flow_root]
            elif data_flow_root not in self.data_flow_origins[data_flow_leaf]:
                self.data_flow_origins[data_flow_leaf].append(data_flow_root)

    def data_flow_backtrack(self, target_nodes):
        for target in target_nodes:
            self.data_flow_backward_traverse(target)
        for instr_node in self.dist.keys():
            self.data_flow_backward_traverse(instr_node, current_data_flow_path=[instr_node])
        print(f"data_flow nodes: {self.data_flow_nodes}")
        return self.data_flow_nodes, self.data_flow_origins