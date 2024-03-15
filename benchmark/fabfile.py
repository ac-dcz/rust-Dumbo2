from fabric import task

from benchmark.local import LocalBench
from benchmark.logs import ParseError, LogParser
from benchmark.utils import Print
from benchmark.plot import Ploter, PlotError
from aws.instance import InstanceManager
from aws.remote import Bench, BenchError


@task
def local(ctx):
    ''' Run benchmarks on localhost '''
    bench_params = {
        'nodes': 4,
        'rate': 10_000,
        'tx_size': 512,
        'faults': 0,
        'duration': 30,
    }
    node_params = {
        'consensus': {
            'sync_timeout': 2_000,
            'timeout_delay': 2_000,
            'sync_retry_delay': 10_000,
            'max_payload_size': 500,
            'min_block_delay': 0,
            'network_delay': 20_000, # message delay on the leaders' proposals during DDoS
            'ddos': False, # True for DDoS attack on the leader, False otherwise
            'random_ddos': False,
            'random_chance': 10,
            'exp': 1 # multiplicative factor for exponential fallback
        },
        'mempool': {
            'queue_capacity': 10_000,
            'sync_retry_delay': 100_000,
            'max_payload_size': 15_000,
            'min_block_delay': 0
        },
        'protocol': 0, # 0 for flexible HBBFT, 1 for other
    }
    try:
        ret = LocalBench(bench_params, node_params).run(debug=False).result()
        print(ret)
    except BenchError as e:
        Print.error(e)


@task
def create(ctx, nodes=2):
    ''' Create a testbed'''
    try:
        InstanceManager.make().create_instances(nodes)
    except BenchError as e:
        Print.error(e)


@task
def destroy(ctx):
    ''' Destroy the testbed '''
    try:
        InstanceManager.make().terminate_instances()
    except BenchError as e:
        Print.error(e)


@task
def start(ctx, max=10):
    ''' Start at most `max` machines per data center '''
    try:
        InstanceManager.make().start_instances(max)
    except BenchError as e:
        Print.error(e)


@task
def stop(ctx):
    ''' Stop all machines '''
    try:
        InstanceManager.make().stop_instances()
    except BenchError as e:
        Print.error(e)


@task
def info(ctx):
    ''' Display connect information about all the available machines '''
    try:
        InstanceManager.make().print_info()
    except BenchError as e:
        Print.error(e)


@task
def install(ctx):
    ''' Install HotStuff on all machines '''
    try:
        Bench(ctx).install()
    except BenchError as e:
        Print.error(e)


@task
def remote(ctx):
    ''' Run benchmarks on AWS '''
    bench_params = {
        'nodes': [50],
        'rate': [35_000, 40_000],
        'tx_size': 512,
        'faults': 0, 
        'duration': 300,
        'runs': 2,
    }
    node_params = {
        'consensus': {
            'sync_timeout': 2000,
            'timeout_delay': 10_000,
            'sync_retry_delay': 100_000,
            'max_payload_size': 1_000,
            'min_block_delay': 100,
            'network_delay': 20_000, # message delay on the leaders' proposals during DDoS
            'ddos': False, # True for DDoS attack on the leader, False otherwise
            'random_ddos': False,
            'random_chance': 0,
            'exp': 5 # multiplicative factor for exponential fallback
        },
        'mempool': {
            'queue_capacity': 100_000,
            'sync_retry_delay': 100_000,
            'max_payload_size': 500_000,
            'min_block_delay': 100
        },
        'protocol': 0, # 0 for 2-chain HotStuff, 1 for Ditto, 2 for 2-chain VABA
    }
    try:
        Bench(ctx).run(bench_params, node_params, debug=False)
    except BenchError as e:
        Print.error(e)


@task
def plot(ctx):
    ''' Plot performance using the logs generated by "fab remote" '''
    plot_params = {
        'nodes': [10, 20, 50],
        'tx_size': 512,
        'faults': [0],
        'max_latency': [3_000, 6_000]
    }
    try:
        Ploter.plot(plot_params)
    except PlotError as e:
        Print.error(BenchError('Failed to plot performance', e))


@task
def kill(ctx):
    ''' Stop any HotStuff execution on all machines '''
    try:
        Bench(ctx).kill()
    except BenchError as e:
        Print.error(e)


@task
def logs(ctx):
    ''' Print a summary of the logs '''
    # try:
    print(LogParser.process('./logs').result())
    # except ParseError as e:
    #     Print.error(BenchError('Failed to parse logs', e))
