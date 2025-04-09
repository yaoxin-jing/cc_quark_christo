import subprocess
import os
import signal
import time
from datetime import datetime
import logging
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import argparse
from pathlib import Path
import numpy as np
import csv

SEPARATE= '====================\n'
TRY = 'Runtime:%s,Turns:%d\n'

def log(_name, path):
    ctime = datetime.now().strftime("%d-%m-%Y_%H-%M-%S");
    end_dir = path.joinpath(_name)
    if end_dir.exists() == False:
        os.makedirs(end_dir.as_posix())
    file_name = end_dir.joinpath(ctime + '.csv')
    return file_name

def startup_time(log_name, runtimes=["quark"], tries=10):
    rtime = ""
    tmp_file = log_name.as_posix() + '.tmp'
    result = subprocess.run("docker create ubuntu:20.04", shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
    cid = result.stdout.split('\n')[0]
    with open(tmp_file, 'a+') as f:
        for r in runtimes:
            if r != 'native':
                rtime = "--runtime="+r
            command = f'date +%s%N;docker run --rm {rtime} ubuntu:20.04 /bin/date +%s%N'
            f.write(TRY % (r, tries))
            f.write(SEPARATE)
            for i in range(tries):
                result = subprocess.run(command, shell=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                vals = result.stdout.split('\n')[:-1]
                diff = (float(vals[1]) - float(vals[0])) * 10**(-9)
                f.write("%.9f\n" % diff)
    _adjust_startup_res(tmp_file, log_name)
    subprocess.run(f"docker rm -f {cid}", shell=True, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.STDOUT)

def redis_ops(log_name, runtimes, tries=100000):
    rtime = ""
    logs = []
    for r in runtimes:
        if r != 'native':
            rtime = "--runtime="+r
        tmp_file = log_name.as_posix() + r + '.csv'
        command = f'docker run --rm {rtime} -p 6379:6379 --name some-redis --rm -it redis'
        #check_ready = "nc -zv localhost 6379"
        check_ready = "ps -e|grep redis &> /dev/null; echo $?"
        check_op = f'redis-benchmark -n {tries} -c 20 --csv'

        with open(tmp_file, 'a', newline='') as f:
            print("file name:", tmp_file)
            try:
                pid = os.fork()
                if pid == 0:
                    subprocess.run(command, shell=True, stdout=subprocess.DEVNULL)
                else:
                    while True:
                        time.sleep(2)
                        result = subprocess.run(check_ready, shell=True, capture_output=True,
                                                text=True)
                        res = result.stdout.split()
                        print("conn:", res[0])
                        if res[0] == '0':
                            break
                    subprocess.run(check_op, shell=True, stdout=f,
                                   stderr=subprocess.STDOUT, text=True)
                    f.flush()
                    os.kill(pid, signal.SIGTERM)
                    os.waitpid(pid, 0)
                    logs.append(tmp_file)
            finally:
                subprocess.run("docker rm -f some-redis", shell=True)
        if len(logs) > 0:
            _adjust_redis_res(logs)
        else:
            print("no logs from redis-ops")

def _adjust_redis_res(files):
    res = {}
    header = ["test"]
    for f in files:
        runtime = f.split('.')[-2]
        header.append(runtime)
        with open(f, 'r', newline='') as _csv:
            _reader = csv.reader(_csv, delimiter=',')
            for r in _reader:
                if r[0] == 'test':
                    continue
                if r[0] in res:
                    res[r[0]].append(r[1])
                else:
                    res[r[0]] = [r[1]]
    log_file = files[0].split('.')[0]
    with open(log_file, 'a', newline='') as f:
        _writer = csv.writer(f)
        _writer.writerow(header)
        for k, v in res.items():
            data = []
            data.append(k)
            row = data + v
            _writer.writerow(row)

def _adjust_startup_res(src_fd, dest_file):
    data = {}
    with open(src_fd, 'r') as fd:
        content = fd.readlines()
        print(content)
        runtime = ""
        times = int((content[0].split(','))[-1].split(':')[-1].replace('\n', ''))
        for i in range(0, len(content) - times, times + 2):
            head = content[i].split(',')
            runtime = head[0].split(':')[-1]
            sum = 0
            for j in range(0, times):
                sum = sum + float(content[i+2+j].replace('\n', ''))
            data[runtime] = "%.9f" % (sum / times)
        print(data)
        with open(dest_file, 'a', newline='') as _csv:
            header = ['test']
            keys = data.keys()
            for k in keys:
                header.append(k)
            row = ['startup']
            for h in header[1:]:
                row.append(data[h])
            _writer = csv.writer(_csv)
            _writer.writerow(header)
            _writer.writerow(row)

def _median(file):
    data = {}
#    with open(file.as_posix(), 'r') as f:
#        content = f.readlines()
#        runtime = ""
#        times = int((content[0].split(','))[-1].split(':')[-1].replace('\n', ''))
#        for i in range(0, len(content) - times, times + 2):
#            head = content[i].split(',')
#            runtime = head[1].split(':')[-1]
#            sum = 0
#            for j in range(0, times):
#                sum = sum + float(content[i+2+j].replace('\n', ''))
#            data[runtime] = sum / times
#    print(data)
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
    #_adjust_redis_res(['/tmp/redis-ops/09-04-2025_12-47-57.tmp.native.csv'])
    #return 0
    #_adjust_startup_res('/tmp/startup/09-04-2025_16-20-28.csv.tmp',
    #                    '/tmp/startup/09-04-2025_16-20-28.csv')
    #return 0
    argpars = argparse.ArgumentParser()
    argpars.add_argument('--type', help='Performance measurement or plot collected data',
                         choices=['startup', 'redis-ops', 'plot'], default='startup')
    argpars.add_argument('--runtime', help='Select the runtime for tests (not applyed for "plot")',
                         choices=['all', 'native', 'runsc', 'quark'], nargs='+', default=['all'])
    log_path_pars = argparse.ArgumentParser(parents=[argpars], add_help=False)
    log_path_pars.add_argument('--path', help='All except "plot":Directory to save measurement \
        \nreport Only for "plot":Create a plot from the passed file', type=Path)
    argpars.add_argument('--for', help='(Temporay command) Select the test type to plot',
                         choices=['startup', 'redis'], nargs=1, default='startup')
    args = log_path_pars.parse_args()
    cmd_type = args.type
    log_path = args.path
    if cmd_type == 'plot':
        build_plot(log_path)
    else:
        lname = log(cmd_type, log_path)
        runtimes = []
        match args.runtime[0]:
            case 'all':
                runtimes = ['native', 'runsc', 'quark']
            case _:
                runtimes = args.runtime
        try:
            match cmd_type:
                case 'startup':
                    startup_time(lname, runtimes)
                case 'redis-ops':
                    redis_ops(lname, runtimes)
                case _:
                    print(f'Error: command \'cmd_type\' not implemented')
                    return 1
        except Exception as ex:
            logging.exception(ex)
            os.remove(lname)
            return

if __name__ == "__main__":
    main()
