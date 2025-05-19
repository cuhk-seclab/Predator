class DistanceCalculator:
    def __init__(self, targets, icfg):
        self.targets = targets
        self.icfg = icfg
        self.dist = {}
        self.divergent_dist = {}
        self.prob = {}
        self.bb_set = {}
        self.nodes_need_calc = []

    def cal_dist(self, node_id):
        p = self.cal_prob(node_id)
        if p == 0:
            return float('inf')
        else:
            return round(1 / p, 3)

    def cal_prob(self, node_id):
        if self.bb_set[node_id] == 0:
            self.bb_set[node_id] = 1
            if node_id in self.targets:
                self.prob[node_id] = 1
            else:
                total_sum = 0
                successors = list(self.icfg.successors(node_id))
                for succ in successors:
                    self.prob[succ] = self.cal_prob(succ)
                    total_sum += self.prob[succ]

                num = len(successors)
                if num > 0:
                    self.prob[node_id] = total_sum / num

            self.bb_set[node_id] = 2

        return self.prob[node_id]

    def sift_divergent_dist(self):
        divergent_dist = {}
        for node_id in self.bb_set.keys():
            if self.icfg.out_degree(node_id) >= 2 or node_id in self.targets:
                has_reachable = False
                has_unreachable = False
                for succ in list(self.icfg.successors(node_id)):
                    if self.prob[succ] == 0.0:
                        has_unreachable = True
                    else:
                        has_reachable = True
                if has_reachable and has_unreachable and self.prob[node_id] != 0.0:
                    divergent_dist[node_id] = round(self.dist[node_id], 2)
        return divergent_dist

    def calculate(self):
        print("Calculating block distance...")
        for node_id in self.icfg.nodes():
            if self.icfg.out_degree(node_id) >= 2 or node_id in self.targets:
                self.nodes_need_calc.append(node_id)
                # for succ in list(self.icfg.successors(node_id)):
                #     self.nodes_need_calc.append(succ)
        for node_id in self.icfg.nodes():
            self.bb_set[node_id] = 0
            self.prob[node_id] = 0
        
        nodes_cal_len = len(self.nodes_need_calc)
        round_num = 1
        for node_id in self.nodes_need_calc:
            self.dist[node_id] = self.cal_dist(node_id)
            # Show progress percentage
            print(f"Calculation progress: {round_num} / {nodes_cal_len}", end="\r")
            round_num += 1

        self.divergent_dist = self.sift_divergent_dist()

        return self.divergent_dist
