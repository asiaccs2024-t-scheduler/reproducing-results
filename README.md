# Reproducing bug finding results on Magma
Download the Magma repository:
```bash
git clone https://github.com/icse2024-t-scheduler/magma-rl-fuzzing.git
cd magma-rl-fuzzing
````

To run Magma experiments we execute:
```bash
./tools/captain/run.sh
```

After the fuzzing campaign has been completed. The experiment files can be extracted by:
```bash
./tools/benchd/exp2json.py ./tools/captain/workdir ./tools/captain/workdir/bugs.json
./tools/benchd/survival_analysis.py -n 10 -t $((72*60*60)) -r ./tools/captain/workdir/bugs.json > ./tools/captain/workdir/survival.csv
```


# Reproducing code coverage results on FuzzBench

## Installing Prerequisites
Running FuzzBench requires Install make for your linux distribution. E.g. for Ubuntu, Python development packages, and rsync to run locally.
```bash
apt-get install build-essential
apt-get install python3.10-dev python3.10-venv
apt-get install rsync
```

## Installing FuzzBench
Download, compile and activate virtual environment.
```bash
git clone https://github.com/icse2024-t-scheduler/fuzzbench
cd fuzzbench
make install-dependencies
source .venv/bin/activate
```

## Running the Experiments in the paper
Run all experiments to reproduce the experiment results in our paper. The number of trials and duration of the experiment can be configured in experiment-config.yaml.
```bash
PYTHONPATH=. python3 experiment/run_experiment.py -a --experiment-config experiment-config.yaml \
  --experiment-name rl-fuzzers --fuzzers aflplusplus_qemu aflhier aflhier_overhead ecofuzz_overhead \
  rl_fuzzing_none_LLVM rl_fuzzing_none_qemu rl_fuzzing_none_qemu_overhead rl_fuzzing_rare_edge_LLVM \
  rl_fuzzing_rare_edge_qemu rl_fuzzing_sample_LLVM rl_fuzzing_sample_qemu rl_fuzzing_sample_qemu_overhead \
  rl_fuzzing_with_sqrt_LLVM rl_fuzzing_with_sqrt_qemu rl_fuzzing_without_sqrt_LLVM rl_fuzzing_without_sqrt_qemu \
  rl_fuzzing_without_sqrt_qemu_overhead
```

# Running t-scheduler Standalone

## Installing Prerequisites

If building with the C++ RL code, install Boost:
```bash
apt-getinstall -y libboost-all-dev
```

## Downloading t-Scheduler
```bash
git clone https://github.com/icse2024-t-scheduler/t-scheduler.git
cd t-scheduler
```

## Building t-Scheduler
Build AFL++:
```bash
make RL_FUZZING=1
```



If building with the Python RL code, use:
```bash
make PY_RL_FUZZING=1
```


Then configure a Python virtualenv (only required if using Python RL):
```bash
python3 -m venv venv
source venv/bin/activate
pip3 install --upgrade pip
pip3 install -r RL-requirements.txt
```
## Begin Fuzzing

Start the Python service:
```bash
./src/RLFuzzing.py
```


Start the fuzzer:
```bash
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_TESTCACHE_SIZE=2

# without rareness : 0
# with rareness : 1
# with rareness and sqrt : 2
# sample rareness : 3
# rare without reinforcement learning : 4
export AFL_RL_CORRECTION_FACTOR=0

./afl-fuzz -i /out/seeds -o /out/corpus -m none -t 1000+ -d -Q -c0 -- /out/fuzz_target 2147483647
```

# Post-Processing Scripts
Post-Processing scripts are available on Python to analyze the experimental data from FuzzBench. They include:
* ```bug_summary.py``` - Performs survival analysis using restricted mean survivial time (RMST) on experimental results from Magma. More details can be found in Supplementary_Material.pdf
* ```cov_summary.py``` - Calculates area under curve (AUC) for experimental results in FuzzBench, and performs Mann-Whitney significance test on edge coverage and AUC.
* ```fuzzer_stats_summary.py``` - Provides statistics on the fuzzer statistics such as executions per second and fuzzer iteration rate.
* ```scheduler_overheads.py``` - Calculates the scheduler overheads
