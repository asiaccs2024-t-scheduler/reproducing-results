#!/usr/bin/env python3

from collections import defaultdict, OrderedDict
from pathlib import Path

import numpy as np
import pandas as pd


THIS_DIR = Path(__file__).parent
DATA_PATH = THIS_DIR.parent / 'data' / 'survival.csv'

FUZZERS = OrderedDict(
    aflplusplus_explore_lto='EXPLORE',
    aflplusplus_lto='FAST',
    aflplusplus_coe_lto='COE',
    aflplusplus_quad_lto='QUAD',
    aflplusplus_lin_lto='LIN',
    aflplusplus_exploit_lto='EXPLOIT',
    aflplusplus_mmopt_lto='MMOPT',
    aflplusplus_rare_lto='RARE',
    k_scheduler='\\texttt{K-Sched}',
    tortoisefuzz='Tortoise',
    aflplusplus_rl_none='\\algoworare',
    aflplusplus_rl_without_sqrt='\\algowrare',
    aflplusplus_rl_sample='\\algosample',
)

TARGETS = [
    'libpng_read_fuzzer',
    'sndfile_fuzzer',
    'tiff_read_rgba_fuzzer',
    'tiffcp',
    'libxml2_xml_read_memory_fuzzer',
    'xmllint',
    'lua',
    'asn1',
    'client',
    'server',
    'x509',
    'exif',
    'pdf_fuzzer',
    'pdfimages',
    'pdftoppm',
    'sqlite3_fuzz',
]

NUM_TRIALS = 10


def main():
    """The main function."""
    # Read the survival data. Ignore the `reached` values: we only care about
    # bugs triggered. Convert the data to long format (via `melt`)
    triggered_cols = ['triggered_%d' % trial for trial in range(0, 10)]
    id_vars = ['target', 'program', 'bug', 'fuzzer']
    df = pd.read_csv(
        DATA_PATH,
        usecols=id_vars + triggered_cols
    ).melt(
        id_vars=id_vars,
        value_vars=triggered_cols,
        var_name='seconds'
    ).drop(
        columns='seconds'
    ).rename(
        columns=dict(value='seconds')
    )
    # Rename fuzzers for the paper
    df['fuzzer'] = df.fuzzer.map(FUZZERS)

    #
    # Target counts
    #

    bug_data = defaultdict(dict)

    # Count the number of bugs triggered across all trials.

    for (program, fuzzer), bugs_df in df.groupby(by=['program', 'fuzzer']):
        count = bugs_df.seconds.dropna().count()
        bug_data[program][fuzzer] = count

    # Initialize an `OrderedDict` (so the targets appear in the order that we
    # want) for transforming into a `DataFrame`
    results = OrderedDict(Target=[])
    for fuzzer in FUZZERS.values():
        results[fuzzer] = []

    # Build the `OrderedDict`
    for target in TARGETS:
        results['Target'].append(target)
        for fuzzer in FUZZERS.values():
            if fuzzer not in bug_data[target]:
                results[fuzzer].append(np.nan)
            else:
                results[fuzzer].append(bug_data[target][fuzzer])

    count_df = pd.DataFrame.from_dict(results)

    style = count_df.style
    style.format(na_rep='\\xmark')
    style.hide(axis='index')
    print(style.to_latex())

    #
    # Total
    #

    totals = df.groupby(['program', 'bug']).apply(
        lambda x: x[~x.seconds.isna()].fuzzer
    )

    print('Totals:')
    for fuzzer in FUZZERS.values():
        print(f'{fuzzer}: {totals.value_counts()[fuzzer]}')
    print('')

    #
    # Best
    #

    best_fuzzers = defaultdict(int)

    print('Best (per target):')
    for target, target_df in count_df.groupby('Target'):
        max_bugs = target_df.max(axis=1, numeric_only=True).values[0]
        best = target_df.loc[:, (target_df == max_bugs).all()]
        for fuzzer in best:
            best_fuzzers[fuzzer] += 1
        print(f'  {target}: {", ".join(best)}')
    print('')

    print('Best:')
    for fuzzer in FUZZERS.values():
        print(f'{fuzzer}: {best_fuzzers[fuzzer]}')
    print('')

    #
    # Unique
    #

    unique = defaultdict(int)
    for (program, fuzzer), fuzz_df in df.groupby(['program', 'fuzzer']):
        bugs = fuzz_df[~fuzz_df.seconds.isna()].bug.unique()
        unique[fuzzer] += len(bugs)

    print('Unique:')
    for fuzzer in FUZZERS.values():
        print(f'{fuzzer}: {unique[fuzzer]}')
    print('')

    #
    # Fastest
    #

    fastest = df[~df.seconds.isna()].groupby(['program', 'bug']).apply(
        lambda x: pd.Series(x[x.seconds == x.seconds.min()].fuzzer.unique())
    )

    print('Fastest:')
    for fuzzer in FUZZERS.values():
        print(f'{fuzzer}: {fastest.value_counts()[fuzzer]}')
    print('')

    #
    # Missed
    #

    # Find all the bugs that were triggered by at least one fuzzer
    all_triggered_bugs = defaultdict(set)
    for (program, bug), bug_df in df.groupby(['program', 'bug']):
        if not bug_df.seconds.isna().all():
            all_triggered_bugs[program].add(bug)

    # Find the bugs triggered by each fuzzer
    triggered = defaultdict(lambda: defaultdict(set))
    for (program, bug, fuzzer), fuzz_df in df.groupby(['program', 'bug', 'fuzzer']):
        # The bug is triggered if it is found in _any_ trial
        if not fuzz_df.seconds.isna().all():
            triggered[fuzzer][program].add(bug)

    print('Missed:')
    for fuzzer in FUZZERS.values():
        # Missed bugs is now the set difference
        missed = []
        for program, bugs in all_triggered_bugs.items():
            missed.extend([bug for bug in (bugs - triggered[fuzzer][program])])
        print(f'{fuzzer}: {len(missed)}')
    print('')

    #
    # Consistency
    #

    print('Consistency')
    for fuzzer in FUZZERS.values():
        consistency = totals.value_counts()[fuzzer] / unique[fuzzer] / NUM_TRIALS
        print(f'{fuzzer}: {consistency:.02f}')
    print('')


if __name__ == '__main__':
    main()