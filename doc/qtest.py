import subprocess
import os
from datetime import datetime
import logging
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import argparse
from pathlib import Path
import numpy as np

SEPARATE= '====================\n'
TRY = 'Runtime:%s,Turns:%d\n'

def log(_name, path):
    ctime = datetime.now().strftime("%d-%m-%Y_%H-%M-%S");
    end_dir = path.joinpath(_name)
    if end_dir.exists() == False:
        os.makedirs(end_dir.as_posix())
    file_name = end_dir.joinpath(ctime)
    with open(file_name, 'x') as f:
        f.write("Test:"+_name+",")
    return file_name

def startup_time(log_name, runtimes=["quark"], tries=10):
    rtime = ""
    for r in runtimes:
        if r != 'native':
            rtime = "--runtime="+r
        command = f'date +%s%N;docker run --rm {rtime} ubuntu:20.04 /bin/date +%s%N'
        with open(log_name, 'a') as f:
            f.write(TRY % (r, tries))
            f.write(SEPARATE)
            for i in range(tries):
                result = subprocess.run(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                vals = result.stdout.split('\n')[:-1]
                diff = (float(vals[1]) - float(vals[0])) * 10**(-9)
                f.write("%.9f\n" % diff)

def _median(file):
    data = {}
    with open(file.as_posix(), 'r') as f:
        content = f.readlines()
        runtime = ""
        times = int((content[0].split(','))[-1].split(':')[-1].replace('\n', ''))
        for i in range(0, len(content) - times, times + 2):
            head = content[i].split(',')
            runtime = head[1].split(':')[-1]
            sum = 0
            for j in range(0, times):
                sum = sum + float(content[i+2+j].replace('\n', ''))
            data[runtime] = sum / times
    print(data)
    return data

def build_plot(file):
    data = _median(file)
    plt.figure(figsize=(3,3))
    names = []
    val = []
    for k, v in data.items():
        names.append(k)
        val.append(v)
    x = np.array(names)
    y = np.array(val)
    plt.bar(x, y)
    plt.show()

def main():
    argpars = argparse.ArgumentParser()
    argpars.add_argument('--type', help='Performance measurement or plot collected data',
                         choices=['startup', 'redis-ops', 'plot'], default='startup')
    argpars.add_argument('--runtime', help='Select the runtime for tests (not applyed for "plot")',
                         choices=['all', 'native', 'runsc', 'quark'], nargs='+', default='all')
    log_path_pars = argparse.ArgumentParser(parents=[argpars], add_help=False)
    log_path_pars.add_argument('--path', help='All except "plot":Directory to save measurement report \
        \nOnly for "plot":Create a plot from the passed file', type=Path)
    args = log_path_pars.parse_args()
    cmd_type = args.type
    log_path = args.path
    if cmd_type == 'plot':
        build_plot(log_path)
    else:
        lname = log(cmd_type, log_path)
        runtime = args.runtime
        runtimes = []
        match args.runtime:
            case 'all':
                runtimes = ['native', 'runsc', 'quark']
            case _:
                runtimes = [args.runtime]
        try:
            match cmd_type:
                case 'startup':
                    startup_time(lname, runtimes)
                case _:
                    print(f'Error: command \'cmd_type\' not implemented')
                    return 1
        except Exception as ex:
            logging.exception(ex)
            os.remove(lname)
            return

if __name__ == "__main__":
    main()
