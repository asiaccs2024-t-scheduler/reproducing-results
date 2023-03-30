#!/usr/bin/env python3


from collections import defaultdict
from pathlib import Path
import re
import sys

import numpy as np
import pandas as pd
from scipy.stats import bootstrap, gmean


FUZZERS = [
    'aflpp_explore_overhead',
    'aflpp_overhead',
    'aflpp_coe_overhead',
    'aflpp_quad_overhead',
    'aflpp_lin_overhead',
    'aflpp_exploit_overhead',
    'aflpp_mmopt_overhead',
    'aflpp_rare_overhead',
    'aflhier_overhead',
    'ecofuzz_overhead',
    'rl_fuzzing_none_qemu_overhead',
    'rl_fuzzing_without_sqrt_qemu_overhead',
    'rl_fuzzing_sample_qemu_overhead',
]

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

TRIAL_RE = re.compile(r'''-trial-(\d+)''')
EXECS_PER_SEC_RE = re.compile(r'''execs_per_sec     : (\d+.\d+)''')


def main(args):
    """The main function."""
    if len(args) < 2:
        print(f'usage: {args[0]} /path/to/fuzzer_stats/dir')
        sys.exit(1)

    data = dict(target=[], fuzzer=[], trial=[], execs=[])

    for stats_path in Path(args[1]).iterdir():
        stats_file = stats_path.name

        try:
            target = next(t for t in TARGETS if stats_file.startswith(t))
            fuzzer = next(f for f in FUZZERS
                          if stats_file[len(target) + 1:].startswith(f))
            trial = int(TRIAL_RE.search(stats_file)[1])
        except StopIteration:
            print(f'Skipping {stats_file}')
            continue

        with stats_path.open() as inf:
            lines = [line for line in inf]
            if not lines:
                print(f'{stats_path} is empty. Skipping')
                continue
            start_time = next(line for line in lines
                              if line.startswith('start_time ')).split(' : ')[1]
            last_update = next(line for line in lines
                               if line.startswith('last_update ')).split(' : ')[1]
            runtime = int(last_update) - int(start_time)

            # If the fuzz run was less than 20 hours, skip it
            # (results are not indicative)
            if runtime / 60 / 60 < 20:
                print(f'{stats_file} runtime {runtime / 60 / 60:.02f} < 20 hours. Skipping')
                continue
            exec_line = next(line for line in lines
                             if line.startswith('execs_per_sec '))
            execs = float(exec_line.split(' : ')[1])

        data['target'].append(target)
        data['fuzzer'].append(fuzzer)
        data['trial'].append(trial)
        data['execs'].append(execs)

    df = pd.DataFrame.from_dict(data)
    fuzzer_execs = defaultdict(list)

    for (target, fuzzer), execs_df in df.groupby(['target', 'fuzzer']):
        execs = execs_df.sort_values('trial').tail(10).execs.mean()
        fuzzer_execs[fuzzer].append(execs)
        print(f'{target},{fuzzer},{execs:.02f}')
    print('')

    print('mean')
    for fuzzer in FUZZERS:
        execs = fuzzer_execs[fuzzer]
        summary = np.mean(execs)
        ci = bootstrap((execs, ), np.mean)
        print(f'{fuzzer} & {summary:0.2f} & {ci.standard_error:0.2f}')
    print('')

    print('median')
    for fuzzer in FUZZERS:
        execs = fuzzer_execs[fuzzer]
        summary = np.median(execs)
        ci = bootstrap((execs, ), np.median)
        print(f'{fuzzer} & {summary:0.2f} & {ci.standard_error:0.2f}')
    print('')

    print('geometric mean')
    for fuzzer in FUZZERS:
        execs = fuzzer_execs[fuzzer]
        summary = gmean(execs)
        ci = bootstrap((execs, ), gmean)
        print(f'{fuzzer} & {summary:0.2f} & {ci.standard_error:0.2f}')
    print('')


if __name__ == '__main__':
    main(sys.argv)
