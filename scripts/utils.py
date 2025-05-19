import os
import re

def map_targets_to_nodes(targets_df, nodes_df):
    target_nodes = []

    for _, row in targets_df.iterrows():
        file_name, lineno = row[0].split(':')
        lineno = int(lineno)

        # Find the target file row
        try:
            file_row = nodes_df[(nodes_df['type'] == 'AST_TOPLEVEL') & (nodes_df['name'] == file_name) & (nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')].iloc[0]
        except IndexError:
            print(f"Target {file_name}:{lineno} is not found.")
            continue
        # Find the target node
        condition = (nodes_df['lineno:int'] == lineno)
        try:
            target_node_ids = nodes_df.loc[file_row.name:].loc[condition]['id:int'].tolist()
        except IndexError:
            print(f"Target node {file_name}:{lineno} is not found.")
            continue
        # Find the next file row
        try:
            next_file_id = nodes_df.loc[file_row.name:].loc[(nodes_df['type'] == 'AST_TOPLEVEL') & (nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')].iloc[1]['id:int']
        except IndexError:
            next_file_id = float('inf')
        # If the target node is not found, print error message
        if len(target_node_ids) and target_node_ids[0] >= next_file_id:
            print(f"Target node {file_name}:{lineno} is not found.")
            continue
        for target_node_id in target_node_ids:
            if target_node_id < next_file_id:
                target_nodes.append(target_node_id)

    print(f"Mapped provided {len(targets_df)} targets to {len(target_nodes)} possible nodes.")
    print(f"Target nodes: {target_nodes}")
    return target_nodes

def map_externals(nodes_df, data_flow_origins, out_file_path):
    save_file = os.path.join(out_file_path, 'data_flow_origins.csv')
    data_flow_origins_copy = data_flow_origins.copy()
    super_globals_pattern = re.compile(r'_(GET|POST|REQUEST|COOKIE)')
    
    for node_id, origins in data_flow_origins_copy.items():
        for origin in origins:
            is_external = False
            # Find the origin node
            try:
                origin_node = nodes_df[nodes_df['id:int'] == origin].iloc[0]
            except IndexError:
                continue
            # Find all nodes before or after the origin node and share the same lineno
            try:
                next_node = nodes_df[nodes_df['id:int'] == origin_node['id:int'] + 1].iloc[0]
                while origin_node['lineno:int'] == next_node['lineno:int']:
                    if super_globals_pattern.search(str(next_node['code'])):
                        is_external = True
                        break
                    next_node = nodes_df[nodes_df['id:int'] == next_node['id:int'] + 1].iloc[0]

                prev_node = nodes_df[nodes_df['id:int'] == origin_node['id:int'] - 1].iloc[0]
                while origin_node['lineno:int'] == prev_node['lineno:int']:
                    if super_globals_pattern.search(str(prev_node['code'])):
                        is_external = True
                        break
                    prev_node = nodes_df[nodes_df['id:int'] == prev_node['id:int'] - 1].iloc[0]
            except IndexError:
                pass
            if not is_external:
                data_flow_origins[node_id].remove(origin)
                
    with open(save_file, 'w') as f:
        for key, values in data_flow_origins.items():
            if values:
                line = f"{key}\t{','.join(map(str, values))}\n"
                f.write(line)



