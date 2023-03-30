#!/usr/bin/env python3


from collections import OrderedDict
from pathlib import Path
import re
import sys

from scipy.stats import bootstrap, gmean
import numpy as np
import pandas as pd


TRIAL_RE = re.compile(r'''_trial-(\d+)_''')

CSV_COLS = ['time', 'overhead', 'update_overhead']
TRIAL_LEN = 24 * 60 * 60

FUZZERS = OrderedDict(
    aflpp_explore_overhead='EXPLORE',
    aflpp_overhead='FAST',
    aflpp_coe_overhead='COE',
    aflpp_quad_overhead='QUAD',
    aflpp_lin_overhead='LIN',
    aflpp_exploit_overhead='EXPLOIT',
    aflpp_mmopt_overhead='MMOPT',
    aflpp_rare_overhead='RARE',
    aflhier_overhead='\\aflhier',
    ecofuzz='EcoFuzz',
    rl_fuzzing_none_qemu_overhead='\\algoworare',
    rl_fuzzing_without_sqrt_qemu_overhead='\\algowrare',
    rl_fuzzing_sample_qemu_overhead='\\algosample',
)

TARGETS = [
    'bloaty_fuzz_target',
    'curl_curl_fuzzer_http',
    'freetype2-2017',
    'harfbuzz-1.3.2',
    'jsoncpp_jsoncpp_fuzzer',
    'lcms-2017-03-21',
    'libjpeg-turbo-07-2017',
    'libpng-1.2.56',
    'mbedtls_fuzz_dtlsclient',
    'openssl_x509',
    'openthread-2019-12-23',
    'php_php-fuzz-parser',
    'proj4-2017-08-14',
    're2-2014-12-09',
    'sqlite3_ossfuzz',
    'systemd_fuzz-link-parser',
    'vorbis-2017-12-11',
    'woff2-2016-05-06',
    'zlib_zlib_uncompress_fuzzer',
]


def calc_overhead(df: pd.DataFrame) -> float:
    if df.empty:
        return np.nan
    last = df.iloc[-1]
    return last.overhead + last.update_overhead


def calc_queue_update_count(df: pd.DataFrame) -> int:
    if df.empty:
        return np.nan
    return len(df)


def calc_queue_update_time(df: pd.DataFrame) -> float:
    if df.empty:
        return np.nan
    return (df.overhead - df.overhead.shift(fill_value=0)).mean() * 1000


def calc_queue_update_variance(df: pd.DataFrame) -> float:
    if df.empty:
        return np.nan
    return np.var((df.overhead - df.overhead.shift(fill_value=0)))


def print_table(df: pd.DataFrame, aggfunc) -> None:
    df = df.pivot_table(values=['overhead'],
                        index=['target'],
                        columns=['fuzzer'],
                        aggfunc=aggfunc)
    df = df.reindex(FUZZERS.values(), axis=1, level=1).sort_index()
    style = df.style
    style.format('{:.2f}', na_rep='\\xmark')
    print(style.to_latex())


def main(args):
    """The main function."""
    if len(args) < 2:
        print(f'usage: {args[0]} /path/to/overhead/dir')
        sys.exit(1)

    data = dict(
        target=[],
        fuzzer=[],
        trial=[],
        update_time=[],
        update_variance=[],
        update_count=[],
        overhead=[]
    )

    for p in Path(args[1]).glob('*.csv.gz'):
        try:
            target = next(t for t in TARGETS if p.name.startswith(t))
            fuzzer = next(f for f in FUZZERS
                          if p.name[len(target) + 1:].startswith(f))
            trial = int(TRIAL_RE.search(p.name)[1])
        except StopIteration:
            print(f'Skipping {p}...')
            continue

        try:
            df = pd.read_csv(p, header=None)
        except Exception as e:
            print(f'Failed to read {p}: {e}')
            continue
        df.columns = CSV_COLS

        data['target'].append(target)
        data['fuzzer'].append(FUZZERS[fuzzer])
        data['trial'].append(trial)
        data['update_time'].append(calc_queue_update_time(df))
        data['update_variance'].append(calc_queue_update_variance(df))
        data['update_count'].append(calc_queue_update_count(df))
        data['overhead'].append(calc_overhead(df))

    df = pd.DataFrame.from_dict(
        data
    ).groupby(
        ['target', 'fuzzer'],
        as_index=False
    ).apply(
        lambda x: x.sort_values('trial').tail(10)
    ).reset_index(drop=True)

    print('\nOverhead gmean')
    print_table(df, gmean)

    def mean_ci(xs):
        return bootstrap((xs, ), statistic=np.mean).standard_error

    def gmean_ci(xs):
        return bootstrap((xs, ), statistic=gmean).standard_error

    print('\nOverhead CI')
    print_table(df, gmean_ci)

    print('\nQueue update time (mean)')
    for fuzzer in FUZZERS.values():
        queue = df[df.fuzzer == fuzzer].update_time.dropna()
        print(f'{fuzzer} -> {np.mean(queue):.2f} +/- {mean_ci(queue):.2f}')

    print('\nQueue update variance (mean)')
    for fuzzer in FUZZERS.values():
        queue = df[df.fuzzer == fuzzer].update_variance.dropna()
        print(f'{fuzzer} -> {np.mean(queue):.2f} +/- {mean_ci(queue):.2f}')

    print('\nQueue update count (gmean)')
    for fuzzer in FUZZERS.values():
        queue = df[df.fuzzer == fuzzer].update_count.dropna()
        print(f'{fuzzer} -> {gmean(queue):.2f} +/- {gmean_ci(queue):.2f}')

    print('\nOverheads (mean)')
    for fuzzer in FUZZERS.values():
        overheads = df[df.fuzzer == fuzzer].overhead.dropna()
        print(f'{fuzzer} -> {np.mean(overheads) / 1000 / 1000 * 24 * 60 * 60:.2f} +/- {mean_ci(overheads) / 1000 / 1000 * 24 * 60 * 60:.2f}')

    sys.exit(0)


if __name__ == '__main__':
    main(sys.argv)
