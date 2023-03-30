#!/usr/bin/env python3

from collections import defaultdict, OrderedDict
from pathlib import Path

import numpy as np
import pandas as pd

from scipy.stats import bootstrap, mannwhitneyu


# THIS_DIR = Path(__file__).parent
# DATA_PATH = THIS_DIR.parent / 'data'
THIS_DIR = Path(__file__).parent
DATA_PATH = THIS_DIR / '..' / 'data' / 'coverage'

FUZZER_DIRS = [
    'rlexp-explore',
    'aflplusplus_qemu',
    'rlexp-coe',
    'rlexp-quad',
    'rlexp-lin',
    'rlexp-exploit',
    'rlexp-mmopt',
    'rlexp-rare',
    'afl-hier',
    'rl-fuzzing-none',
    'rl-fuzzing-without-sqrt',
    'rl-fuzzing-sample',
]
FUZZERS = OrderedDict(
    rlexp_afl_qemu_explore='EXPLORE',
    aflplusplus_qemu='FAST',
    rlexp_afl_qemu_coe='COE',
    rlexp_afl_qemu_quad='QUAD',
    rlexp_afl_qemu_lin='LIN',
    rlexp_afl_qemu_exploit='EXPLOIT',
    rlexp_afl_qemu_mmopt='MMOPT',
    rlexp_afl_qemu_rare='RARE',
    aflhier='afl-hier',
    rl_fuzzing_none='\\algoworare',
    rl_fuzzing_without_sqrt='\\algowrare',
    rl_fuzzing_sample='\\algosample',
)

def combined_data():
    data_df = []
    for fuzzer_dir in FUZZER_DIRS:
        fuzzer_data_path = DATA_PATH / fuzzer_dir / 'data.csv.gz'
        df = pd.read_csv(fuzzer_data_path)
        data_df.append(df)
    data_df = pd.concat(data_df, axis=0)
    return data_df

def compute_coverage_and_AUC(df):
    
    fuzzers = np.unique(df['fuzzer'].values)
    benchmarks = np.unique(df['benchmark'].values)
    
    coverage = dict(target=[], fuzzer=[], coverage=[])
    AUC = dict(target=[], fuzzer=[], AUC=[])
    for benchmark in benchmarks:
        if benchmark == 'libpcap_fuzz_both':
            continue
        for fuzzer in fuzzers:
            fuzzers = np.unique(df['fuzzer'].values)
            benchmarks = np.unique(df['benchmark'].values)
            idx = (df['fuzzer'] == fuzzer) & (df['benchmark'] == benchmark)
            fuzzer_df = df.loc[idx,:]
            for trial_id in np.unique(fuzzer_df['trial_id']):
                trial_idx = fuzzer_df['trial_id'] == trial_id
                time = fuzzer_df.loc[trial_idx,'time'].values
                
                edge_coverage = fuzzer_df.loc[trial_idx,'edges_covered'].values
                coverage['target'].append(benchmark)
                coverage['fuzzer'].append(fuzzer)
                coverage['coverage'].append(edge_coverage[np.argmax(time)])
                
                AUC['target'].append(benchmark)
                AUC['fuzzer'].append(fuzzer)
                AUC['AUC'].append(np.sum(edge_coverage[1:] / (time[1:] - time[:-1])))
    return coverage, AUC


def print_table(df: pd.DataFrame, aggfunc) -> None:
    df = df.pivot_table(index=['target'],
                        columns=['fuzzer'],
                        aggfunc=aggfunc)
    df = df.reindex(FUZZERS.values(), axis=1, level=1).sort_index()
    style = df.style
    style.format('{:.2f}', na_rep='')
    print(style.to_latex())

def sig_diff(df, coverage_or_AUC):
    fuzzers = np.unique(df['fuzzer'].values)
    benchmarks = np.unique(df['target'].values)


    best_value = dict(target=[], fuzzer=[], mean_value=[], no_sig_diff=[])
    for benchmark in benchmarks:
        if benchmark == 'libpcap_fuzz_both':
            continue
        for fuzzer_1 in fuzzers:
            benchmark_idx = df['target'] == benchmark
            fuzzer_1_idx =  df['fuzzer'] == fuzzer_1
            values_1 = df.loc[benchmark_idx & fuzzer_1_idx, coverage_or_AUC]
            mean_value = np.mean(values_1)

            no_sig_diff = list()
            for fuzzer_2 in fuzzers:
                fuzzer_2_idx =  df['fuzzer'] == fuzzer_2
                values_2 = df.loc[benchmark_idx & fuzzer_2_idx, coverage_or_AUC]
                if ((np.sum(values_1) == 0) or (np.sum(values_2) == 0)):
                    continue

                U1, p = mannwhitneyu(values_1, values_2)
                if p > 0.05:
                    no_sig_diff.append(fuzzer_2)

            best_value['target'].append(benchmark)
            best_value['fuzzer'].append(fuzzer_1)
            best_value['mean_value'].append(mean_value)
            best_value['no_sig_diff'].append(no_sig_diff)

    return best_value

def print_best_value(df, best_value):
    benchmarks = np.unique(df['target'].values)
    best_value_df = pd.DataFrame.from_dict(best_value)
    for benchmark in benchmarks:
        benchmark_idx = best_value_df['target'] == benchmark
        best = best_value_df.loc[best_value_df.loc[benchmark_idx, 'mean_value'].idxmax(),:]
        print('target:', best['target'], 'fuzzers:', set([best['fuzzer']]) | set(best['no_sig_diff']))
        
    

def main():
    """The main function."""
    df = combined_data()
    coverage, AUC = compute_coverage_and_AUC(df)
    
    fuzzers = np.unique(df['fuzzer'].values)
    benchmarks = np.unique(df['benchmark'].values)
    
    print('=======START COVERAGE=======')
    df = pd.DataFrame.from_dict(coverage)
    df['fuzzer'] = df.fuzzer.map(FUZZERS)
    df = df.dropna()

    # Print means
    print_table(df, np.mean)

    # Print CIs
    ci = lambda xs: bootstrap((xs + (np.random.rand(len(xs)) * (1e-7)), ), statistic=np.mean).standard_error
    print_table(df,ci)
    
    sig_diff_coverage = sig_diff(df, 'coverage')
    print_best_value(df, sig_diff_coverage)
    print('=======END COVERAGE=======')
    
    print('=======START AUC=======')
    df = pd.DataFrame.from_dict(AUC)
    df['fuzzer'] = df.fuzzer.map(FUZZERS)
    df = df.dropna()
    
    # Print means
    print_table(df, np.mean)

    # Print CIs
    ci = lambda xs: bootstrap((xs + (np.random.rand(len(xs)) * (1e-7)), ), statistic=np.mean).standard_error
    print_table(df,ci)
    

    sig_diff_AUC = sig_diff(df, 'AUC')
    print_best_value(df, sig_diff_AUC)
    print('=======END AUC=======')



if __name__ == '__main__':
    main()