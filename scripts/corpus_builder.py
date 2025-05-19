import os
import re
import json
import pandas as pd
pd.set_option('future.no_silent_downcasting', True)

class CorpusBuilder:
    def __init__(self, instrumented_files, data_flow_nodes, dist, ast, added_cg_edges, nodes_df, out_file_path):
        self.instrumented_files = instrumented_files
        self.data_flow_nodes = data_flow_nodes
        self.dist = dist
        self.ast = ast
        self.added_cg_edges = added_cg_edges
        self.nodes_df = nodes_df
        self.out_file_path = out_file_path
        self.super_globals = ['_GET', '_POST', '_REQUEST', '_COOKIE']
        self.interesting_types = ['string', 'integer']
        self.exclude_pattern = re.compile(r'\s+|\\n+|\\+|\'+|\<+|\>+|\/+|_(GET|POST|REQUEST|COOKIE|SESSION|SERVER)')
        self.exclude_asts = ['AST_STMT_LIST', 'AST_PARAM_LIST', 'AST_CALL']
        self.interesting_asts = ['AST_IF', 'AST_SWITCH', 'AST_WHILE', 'AST_FOR', 'AST_FOREACH', 'AST_DO_WHILE', 'AST_ASSIGN']
        self.special_terms = [r"&%5C'", r"&%5C%5C%5C'", r"&%df%5c%27", r"&[1,2,3]", r"&(", r"&)", r"&'", r"&#", r"&--+", r"&`", r"&';+foo;+--+", r"&%27", r"&%5C%27", r"&%5C%5C%5C%27", r"&Jw==", r"&KA==", r"&KQ==", r"&;", r"&%26%26", r"&|", r"&%26", r"&%3B", r"&/**/", r"&/*", r"&%5C%5C%5C%22", r"&Eval(foo(bar););", r"&System(foo(bar););"]
        self.xss_terms = [
            r"&<SCRIPT>alert(290363)</SCRIPT>",  
            r"&\"><SCRIPT>alert(290363)</SCRIPT>",                  
            r"&javascript:alert(290363)",
            r"&JaVaScRiPt:alert(290363)",
            r"&JaVaScRiPt:alert(&quot;290363&quot;)",
            r"&jav&#x09;ascript:alert(290363);",
            r"&jav&#x0A;ascript:alert(290363);",
            r"&jav&#x0D;ascript:alert(290363);",
            r"&' ONLOAD='alert(290363)",
            r"&%26%2339%3B-alert(290363)-%26%2339%3B",
            r"&' onmouseover='alert(290363)",          
            r"&JaVaScRiPt:alert(&quot;290363&quot;)",
            r"&\" ONLOAD=\"alert(290363)",
            r"&\" onmouseover=\"alert(290363)",            
            r"&JaVaScRiPt:alert(&quot;290363&quot;)",
            r"&jav&#x09;ascript:alert(290363);",
            r"&jav&#x0A;ascript:alert(290363);",
            r"&jav&#x0D;ascript:alert(290363);",
            r"& ONLOAD=alert(290363)",
            r"&-alert(290363)"
        ]

    def forward_extract_traverse(self, node_id, visited=None):
        successors = list(self.ast.successors(node_id))
        if visited is None:
            visited = set()
        if node_id in visited:
            return
        visited.add(node_id)
        if not successors:
            node = self.nodes_df[self.nodes_df['id:int'] == node_id].iloc[0]
            if node['type'] in self.interesting_types:
                self.value_dic[node['id:int']] = str(node['code'])
        else:
            for succ in successors:
                try:
                    succ_node = self.nodes_df[self.nodes_df['id:int'] == succ].iloc[0]
                except IndexError:
                    continue
                if succ_node['type'] in self.exclude_asts:
                    continue
                self.forward_extract_traverse(succ, visited)

    def extract_request_data(self):
        print("Extracting request data...")
        working_dir = self.out_file_path
        save_file = os.path.join(working_dir, 'request_data.json')
        f = open(save_file, 'w')
        site_groups = []
        sites_to_remove = []
        top_dic = {}
        req = {}
        all_input_set = []
        req_id = 0
        extracted_nodes = {}
        all_file_len = len(self.instrumented_files)
        file_round_num = 1

        for file_name in self.instrumented_files.values():
            print(f"[{file_round_num} / {all_file_len}] Processing file {file_name}:")    
            file_round_num += 1    
            req_info = {"_id": req_id, "_url": "http://localhost/" + file_name}
            if 'moderator' in file_name:
                req_info = {"_id": req_id, "_url": "http://localhost/phpvibe/moderator/?sk=" + file_name[18:-4]}
            req_id += 1
            init_critical_kvs = {}
            possible_super_kvs = {}
            other_kvs_list = []

            try:
                file_row = self.nodes_df[(self.nodes_df['type'] == 'AST_TOPLEVEL') & (self.nodes_df['name'] == file_name) & (self.nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')].iloc[0]
            except IndexError:
                print(f"Target {file_name} is not found.")
                continue

            try:
                next_file_id = self.nodes_df.loc[file_row.name:].loc[(self.nodes_df['type'] == 'AST_TOPLEVEL') & (self.nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')].iloc[1]['id:int']
            except IndexError:
                next_file_id = float('inf')

            all_nodes_in_file = self.nodes_df.loc[(self.nodes_df['id:int'] > file_row['id:int']) & (self.nodes_df['id:int'] < next_file_id)]
            dist_data_flow_linenos_mask = (all_nodes_in_file['id:int'].isin(self.dist.keys()) | all_nodes_in_file['id:int'].isin(self.data_flow_nodes.keys()))
            dist_data_flow_linenos = all_nodes_in_file.loc[dist_data_flow_linenos_mask, ['id:int', 'lineno:int']].set_index('id:int')['lineno:int'].to_dict()
            super_global_condition = (all_nodes_in_file['code'].str.contains('|'.join(self.super_globals))).fillna(False).astype(bool)
            nodes_to_extract_super_kv = all_nodes_in_file.loc[super_global_condition]

            if nodes_to_extract_super_kv['code'].str.contains('_POST').any() or all_nodes_in_file['code'].str.contains('php://input').any():
                req_info['_method'] = "POST"
            else:
                req_info['_method'] = "GET"
            req_info['key'] = req_info['_method'] + ' ' + req_info['_url']

            data_flow_condition = (all_nodes_in_file['code'].str.contains('|'.join(self.data_flow_nodes.values()))).fillna(False).astype(bool)
            nodes_with_data_flow_nodes = all_nodes_in_file.loc[data_flow_condition]
            dist_condition = (all_nodes_in_file['id:int'].isin(self.dist.keys())).fillna(False).astype(bool)
            nodes_with_dist = all_nodes_in_file.loc[dist_condition]

            if self.added_cg_edges.get(nodes_with_dist.iloc[0]['id:int']) is not None:
                caller_filename = ''
                callee_filename = ''
                file_ids = list(self.instrumented_files.keys())
                file_ids.sort()
                for file_id in file_ids:
                    if self.added_cg_edges.get(nodes_with_dist.iloc[0]['id:int']) > file_id:
                        caller_filename = self.instrumented_files[file_id]
                    if nodes_with_dist.iloc[0]['id:int'] > file_id:
                        callee_filename = self.instrumented_files[file_id]
                group_found = False
                for group in site_groups:
                    if caller_filename in group:
                        group.append(callee_filename)
                        sites_to_remove.append(callee_filename)
                        group_found = True
                        break
                if not group_found:
                    site_groups.append([caller_filename, callee_filename])
                    sites_to_remove.append(callee_filename)

            for node_id, key in self.data_flow_nodes.items():
                if file_row['id:int'] < node_id < next_file_id:
                    possible_super_kvs[str(key)] = ''

            for _, node in nodes_with_data_flow_nodes.iterrows():
                try:
                    succ_node = all_nodes_in_file[all_nodes_in_file['id:int'] == node['id:int'] + 1].iloc[0]
                except IndexError:
                    continue
                if succ_node['type'] == 'string' and self.exclude_pattern.search(str(succ_node['code'])) is None:
                    if succ_node['code'] in self.data_flow_nodes.values():
                        init_critical_kvs[str(succ_node['code'])] = ''
                    elif str(succ_node['code']) != 'nan':
                        other_kvs_list.append('&' + str(succ_node['code']))
            for _, node in nodes_to_extract_super_kv.iterrows():
                try:
                    succ_node = all_nodes_in_file[all_nodes_in_file['id:int'] == node['id:int'] + 1].iloc[0]
                except IndexError:
                    continue
                if succ_node['type'] == 'string' and self.exclude_pattern.search(str(succ_node['code'])) is None:
                    if succ_node['code'] in self.data_flow_nodes.values() or succ_node['lineno:int'] in dist_data_flow_linenos.values():
                        init_critical_kvs[str(succ_node['code'])] = ''
                    else:
                        possible_super_kvs[str(succ_node['code'])] = ''

            all_keys = list(init_critical_kvs.keys()) + list(possible_super_kvs.keys())
            all_key_len = len(all_keys)
            key_round_num = 1
            for key in all_keys:
                print(f"Extraction progress: {key_round_num} / {all_key_len}", end="\r")
                key_round_num += 1
                try:
                    key_condition = (all_nodes_in_file['code'] == key).fillna(False).astype(bool)
                    nodes_to_extract_possible_value_for_a_key = all_nodes_in_file.loc[key_condition]
                except re.error:
                    continue
                for _, node in nodes_to_extract_possible_value_for_a_key.iterrows():
                    if extracted_nodes.get(node['id:int']) is None:
                        ast_node = node
                        found = True
                        max_depth = 50
                        while ast_node['type'] not in self.interesting_asts and max_depth > 0:
                            max_depth -= 1
                            pred_node_ids = list(self.ast.predecessors(ast_node['id:int']))
                            try:
                                ast_node = all_nodes_in_file[all_nodes_in_file['id:int'] == pred_node_ids[0]].iloc[0]
                            except IndexError:
                                found = False
                                break
                        if not found:
                            continue
                        else:
                            self.value_dic = {}
                            self.forward_extract_traverse(ast_node['id:int'])
                            extracted_nodes[node['id:int']] = self.value_dic
                            for node_id in self.value_dic.keys():
                                extracted_nodes[node_id] = self.value_dic
                    else:
                        self.value_dic = extracted_nodes[node['id:int']]
                    
                    if key not in self.value_dic.values():
                        continue
                    for node_id, value in self.value_dic.items():
                        if value not in all_keys and value not in self.super_globals and self.exclude_pattern.search(value) is None:
                            value_lineno = all_nodes_in_file[all_nodes_in_file['id:int'] == node_id].iloc[0]['lineno:int']
                            if value == 'nan':
                                value = ''
                            if init_critical_kvs.get(key) is not None and value_lineno in dist_data_flow_linenos.values():
                                init_critical_kvs[key] = value
                            if possible_super_kvs.get(key) is not None:
                                possible_super_kvs[key] = value
                            other_kvs_list.append('='.join([key, value]))
                            other_kvs_list.append('&' + value)

            init_critical_kvs_list = ['='.join([k, v]) for k, v in init_critical_kvs.items()]
            possible_super_kvs_list = ['='.join([k, v]) for k, v in possible_super_kvs.items()]
            req_info['_pivotal_input_set'] = init_critical_kvs_list

            req[req_info['key']] = req_info
            all_input_set += init_critical_kvs_list + possible_super_kvs_list + other_kvs_list
            all_input_set = list(set(all_input_set))

        req_sifted = req.copy()
        for group in site_groups:
            sites_to_update = []
            common_pivotal_input_set = []
            for site_path in group:
                for req_key, req_value in req.items():
                    if req_value['_url'] == "http://localhost/" + site_path:
                        common_pivotal_input_set += req_value['_pivotal_input_set']
                        if req_value['_url'].replace("http://localhost/", "") in sites_to_remove:
                            if req_sifted.get(req_value['key']) is not None:
                                req_sifted.pop(req_value['key'])
                        else:
                            sites_to_update.append(req_value['key'])
                        break
            for req_key in sites_to_update:
                req_sifted[req_key]['_pivotal_input_set'] = list(set(common_pivotal_input_set))

        include_sites = {}
        for req_key, req_value in req_sifted.items():
            file_name_include = req_value['_url'].split('/')[-1]
            if file_name_include.endswith('.php'):
                try:
                    include_condition = (self.nodes_df['name'].str.contains(file_name_include) & (self.nodes_df['type'] == 'string')).fillna(False).astype(bool)
                    include_file_rows = self.nodes_df.loc[include_condition]
                    for _, include_file_row in include_file_rows.iterrows():
                        lineno = include_file_row['lineno:int']
                        while True:
                            pred_node_id = next(self.ast.predecessors(include_file_row['id:int']))
                            include_file_row = self.nodes_df[self.nodes_df['id:int'] == pred_node_id].iloc[0]
                            if include_file_row['type'] == 'AST_INCLUDE_OR_EVAL' and include_file_row['flags:string_array'] != 'EXEC_EVAL':
                                top_file_row = self.nodes_df[self.nodes_df['id:int'] == include_file_row['funcid:int']].iloc[0]
                                tmp_key = req_value['_method'] + ' ' + "http://localhost/" + top_file_row['name']
                                tmp_value = req_value.copy()
                                tmp_value['_id'] += 1000
                                tmp_value['_url'] = "http://localhost/" + top_file_row['name']
                                tmp_value['key'] = tmp_key
                                include_sites[tmp_key] = tmp_value
                                break
                except IndexError:
                    continue
        req_sifted.update(include_sites)

        for req_key, req_value in req_sifted.items():
            if req_value['_method'] == "POST":
                if req_value['_pivotal_input_set'] != []:
                    req_value['_postData'] = '&'.join(req_value['_pivotal_input_set'])
                else:
                    req_value['_postData'] = "&predator=fuzz"
            else:
                if req_value['_pivotal_input_set'] != []:
                    req_value['_url'] = req_value['_url'] + '?' + '&'.join(req_value['_pivotal_input_set'])
                else:
                    req_value['_url'] = req_value['_url'] + '?' + "predator=fuzz"

        top_dic['requestsFound'] = req_sifted
        all_input_set += self.special_terms
        all_input_set += self.xss_terms
        top_dic['inputSet'] = all_input_set

        json.dump(top_dic, f)
        f.close()
        print(f"Request data saved to {save_file}")