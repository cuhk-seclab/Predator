import os
import pandas as pd

class CSVManager:
    def __init__(self, working_dir):
        self.working_dir = working_dir
        self.nodes_file_path = os.path.join(working_dir, 'nodes.csv')
        self.rels_file_path = os.path.join(working_dir, 'rels.csv')
        self.cpg_edges_file_path = os.path.join(working_dir, 'cpg_edges.csv')
        self.targets_file_path = os.path.join(working_dir, 'targets.csv')

    def read_csv(self, file_path, sep='\t', header=0, escapechar='\\', low_memory=False):
        try:
            return pd.read_csv(file_path, sep=sep, escapechar=escapechar, header=header, low_memory=low_memory, encoding='utf-8', on_bad_lines='warn')
        except UnicodeDecodeError:
            return pd.read_csv(file_path, sep=sep, escapechar=escapechar, header=header, low_memory=low_memory, encoding='latin-1', on_bad_lines='warn')
        except TypeError:
            return pd.read_csv(file_path, sep=sep, escapechar=escapechar, header=header, low_memory=low_memory, error_bad_lines=False, warn_bad_lines=True, encoding='latin-1')
            
    def read_csvs(self):
        print("Reading nodes.csv...")
        nodes_df = self.read_csv(self.nodes_file_path)

        print("Reading rels.csv...")
        rels_df = self.read_csv(self.rels_file_path)

        print("Reading cpg_edges.csv...")
        cpg_edges_df = self.read_csv(self.cpg_edges_file_path)

        print("Reading targets.csv...")
        targets_df = self.read_csv(self.targets_file_path, header=None)

        return nodes_df, rels_df, cpg_edges_df, targets_df

    def save_to_csv(self, nodes_to_instrument, nodes_df, instrumented_callee_nodes, out_file_path):
        save_file = os.path.join(out_file_path, 'instr-info.csv')
        instrumented_files = {}

        file_names = nodes_df[(nodes_df['type'] == 'AST_TOPLEVEL') & (nodes_df['flags:string_array'] == 'TOPLEVEL_FILE')].set_index('id:int')['name'].to_dict()
        linenos_mask = nodes_df['id:int'].isin(nodes_to_instrument['dist'].keys()) | nodes_df['id:int'].isin(nodes_to_instrument['data_flow'].keys())
        linenos = nodes_df.loc[linenos_mask, ['id:int', 'lineno:int']].set_index('id:int')['lineno:int'].to_dict()

        with open(save_file, 'w') as f:
            f.write("\t".join(['id', 'type', 'lineno', 'value']) + "\n")
            file_names[float('inf')] = 'end'
            file_id_list = list(file_names.keys())
            for i in range(len(file_id_list) - 1):
                lines_to_write = []
                file_name = str(file_names[file_id_list[i]])
                lines_to_write.append("\t".join([str(file_id_list[i]), 'f', '0', file_name]) + "\n")
                for ni, ln in linenos.items():
                    if ni >= file_id_list[i] and ni < file_id_list[i + 1]:
                        if nodes_to_instrument['dist'].get(ni) is not None:
                            dist = nodes_to_instrument['dist'][ni]
                            try:
                                if ni in instrumented_callee_nodes:
                                    lines_to_write.append("\t".join([str(ni), 'e', str(int(ln)), str(dist)]) + "\n")
                                else:
                                    lines_to_write.append("\t".join([str(ni), 'd', str(int(ln)), str(dist)]) + "\n")
                            except ValueError:
                                pass
                        if nodes_to_instrument['data_flow'].get(ni) is not None:
                            data_flow = nodes_to_instrument['data_flow'][ni]
                            try:
                                lines_to_write.append("\t".join([str(ni), 't', str(int(ln)), data_flow]) + "\n")
                            except ValueError:
                                pass
                
                lines_to_write.sort(key=lambda x: int(x.split('\t')[2]))
                if len(lines_to_write) > 1:
                    f.writelines(lines_to_write)
                    instrumented_files[file_id_list[i]] = file_name

        print(f"Instrumentation info saved to {save_file}")
        return instrumented_files
