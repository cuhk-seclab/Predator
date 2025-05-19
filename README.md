# Predator

Predator is a directed fuzzing-based Web application vulnerability validation prototype. It automates verifying static vulnerability reports by targeting specific code locations.

---

## Installation
All dependencies are containerized via Docker.  
```bash
cd docker && ./build-all.sh
```

## Usage

### Start container for target application (e.g., bWAPP)

```bash
testid=bwapp; plus=vul1; docker kill $testid-$plus; sleep 1; docker run -p 8080:80 -id --rm --name $testid-$plus -w $(pwd) witcher/directphp7run  && docker exec -it -u wc $cve-$plus bash
```

### Required files in the container

- `/test` directory:
  - `witcher_config.json`: Fuzzing configuration
  - `request_data.json`: Seed input data
- `/tmp` directory:
  - `instr-info.csv`: Instrumentation metadata
  - `data_flow_origins.csv`: Taint metadata

### How to generate the required files

For testing bWAPP, first use tools like PHPJoern or TChecker to analyze the app and obtain the following files:

- `nodes.csv`
- `rels.csv`
- `cpg_edges.csv`

Next, provide the `targets.csv` file to specify the target in the format `filename:lineno`. It is recommended to test with only one target at a time to measure `time-to-exposure`, as specifying multiple targets can introduce irrelevant content into the input corpus that is not related to a specific given target.

Then you need to place these files into the working directory

```bash
Predator/working/tchecker-results/bWAPP
```

Next, run scripts in `Predator/scripts/` to obtain the required files and place them in the corresponding folders in the container.

### Start fuzzing

You can execute the command `p` as user `wc` to start fuzzing.

## Contact

For a timely reply, feel free to email us at clwang23@cse.cuhk.edu.hk.

## Citation

```
@inproceedings{wang2024predator,
  title={Predator: Directed Web Application Fuzzing for Efficient Vulnerability Validation},
  author={Wang, Chenlin and Meng, Wei and Luo, Changhua and Li, Penghui},
  booktitle={2025 IEEE Symposium on Security and Privacy (SP)},
  pages={66--66},
  year={2024},
  organization={IEEE Computer Society}
}
```

