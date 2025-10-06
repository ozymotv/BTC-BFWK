#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Plutus Bitcoin Brute Forcer - 24/7 stable RAM + accurate CPU limiter

import platform
import multiprocessing
from multiprocessing import Manager
import hashlib
import binascii
import os
import sys
import time
import signal
import tempfile

# Optional CPU priority management
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Bloom filter (mmap-backed, shared across processes)
# Try both module names for pybloomfiltermmap3
try:
    import pybloomfilter as _pybf
    pybloomfilter = _pybf
    BLOOM_AVAILABLE = True
except Exception:
    try:
        import pybloomfiltermmap3 as _pybf
        pybloomfilter = _pybf
        BLOOM_AVAILABLE = True
    except Exception:
        BLOOM_AVAILABLE = False

# ECDSA backends
from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey

# Paths and constants
DATABASE_DIR = r'database/latest/'
BLOOM_FILE = 'suffixes.bloom'
BLOOM_ERROR_RATE = 0.001  # 0.1% FP target; full verification remains
SEED_FILE = 'plutus_seed.txt'
PROGRESS_SAVE_INTERVAL = 1_000_000
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

shutdown_flag = None

def create_new_seed():
    try:
        seed = binascii.hexlify(os.urandom(32)).decode('utf-8').upper()
        with open(SEED_FILE, 'w', encoding='utf-8') as f:
            f.write('seed: {}\n'.format(seed))
            f.write('counter: 0\n')
            f.write('created: {}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S")))
        print('Created new seed file:', SEED_FILE)
        print('Seed:', seed)
        return seed, 0
    except Exception as e:
        print('Error creating seed file:', e)
        sys.exit(-1)

def load_seed_and_counter():
    seed, counter = None, 0
    try:
        if os.path.exists(SEED_FILE):
            with open(SEED_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    s = line.strip()
                    if s.startswith('seed:'):
                        seed = s.split(':', 1)[1].strip()
                    elif s.startswith('counter:'):
                        counter = int(s.split(':', 1)[1].strip())
            if seed is None or len(seed) != 64:
                raise ValueError('Invalid seed format')
            int(seed, 16)
            print('Loaded seed file:', SEED_FILE)
            print('Seed:', seed)
            print('Starting counter:', counter)
        else:
            seed, counter = create_new_seed()
    except Exception as e:
        print('Error loading seed file:', e)
        seed, counter = create_new_seed()
    return seed, counter

def save_progress_atomic(seed, counter, lock=None):
    # Single-writer with atomic replace; avoids temp-name collisions and races
    temp_dir = os.path.dirname(os.path.abspath(SEED_FILE)) or '.'
    if lock is not None:
        lock.acquire()
    try:
        tf = tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=temp_dir, delete=False)
        try:
            tf.write('seed: {}\n'.format(seed))
            tf.write('counter: {}\n'.format(counter))
            tf.write('updated: {}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S")))
            tf.flush()
            os.fsync(tf.fileno())
            tmp_path = tf.name
        finally:
            tf.close()
        os.replace(tmp_path, SEED_FILE)  # atomic on POSIX/Windows
    except Exception as e:
        print('Error saving progress atomically:', e)
        try:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
    finally:
        if lock is not None:
            lock.release()

def generate_private_key_deterministic(seed, counter):
    try:
        seed_bytes = bytes.fromhex(seed)
        counter_bytes = counter.to_bytes(32, byteorder='big')
        hash_result = hashlib.sha256(seed_bytes + counter_bytes).digest()
        private_int = int.from_bytes(hash_result, byteorder='big')
        if private_int == 0 or private_int >= SECP256K1_ORDER:
            private_int = (private_int % (SECP256K1_ORDER - 1)) + 1
        private_key = '{:064X}'.format(private_int)
        return private_key
    except Exception:
        return None

def private_key_to_public_key(private_key, use_fastecdsa):
    try:
        if not private_key or len(private_key) != 64:
            return None
        int(private_key, 16)
        if use_fastecdsa:
            key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
            public_key = '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
        else:
            pk = PrivateKey().fromString(bytes.fromhex(private_key))
            public_key = '04' + pk.publicKey().toString().hex().upper()
        if len(public_key) != 130 or not public_key.startswith('04'):
            return None
        return public_key
    except Exception:
        return None

def public_key_to_address(public_key):
    try:
        if not public_key or len(public_key) != 130 or not public_key.startswith('04'):
            return None
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        rip = hashlib.new('ripemd160')
        enc = binascii.unhexlify(public_key.encode())
        rip.update(hashlib.sha256(enc).digest())
        vh160 = '00' + rip.hexdigest()
        d1 = hashlib.sha256(binascii.unhexlify(vh160.encode())).digest()
        checksum = hashlib.sha256(d1).hexdigest()[0:8]
        payload = vh160 + checksum
        n = int(payload, 16)
        out = []
        while n > 0:
            n, r = divmod(n, 58)
            out.append(alphabet[r])
        pad = 0
        for i in range(0, len(payload), 2):
            if payload[i:i+2] == '00':
                pad += 1
            else:
                break
        out.extend(alphabet[0] for _ in range(pad))
        address = ''.join(reversed(out))
        if not address or address[0] != '1':
            return None
        if not (26 <= len(address) <= 35):
            return None
        return address
    except Exception:
        return None

def private_key_to_wif(private_key):
    try:
        if not private_key or len(private_key) != 64:
            return None
        digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
        var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
        raw = binascii.unhexlify('80' + private_key + var[0:8])
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        value = 0
        for i, c in enumerate(raw[::-1]):
            value += 256 ** i * c
        result = ''
        while value >= len(alphabet):
            value, mod = divmod(value, len(alphabet))
            result = alphabet[mod] + result
        result = alphabet[value] + result
        pad = 0
        for c in raw:
            if c == 0:
                pad += 1
            else:
                break
        wif = alphabet[0] * pad + result
        if not (50 <= len(wif) <= 52):
            return None
        return wif
    except Exception:
        return None

def save_found_key(private_key, public_key, address, counter, process_id, log_lock=None):
    wif_key = private_key_to_wif(private_key) or 'ERROR_GENERATING_WIF'
    result = '\n' + '='*70 + '\n'
    result += 'FOUND FUNDED ADDRESS!\n'
    result += '='*70 + '\n'
    result += 'hex private key: {}\n'.format(private_key)
    result += 'WIF private key: {}\n'.format(wif_key)
    result += 'public key: {}\n'.format(public_key)
    result += 'address: {}\n'.format(address)
    result += 'counter: {}\n'.format(counter)
    result += 'process: {}\n'.format(process_id)
    result += 'timestamp: {}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S"))
    result += '='*70 + '\n\n'

    targets = [
        'plutus.txt',
        'plutus_backup_{}.txt'.format(int(time.time())),
        'found_key_{}_{}.txt'.format(counter, process_id)
    ]
    saved = False
    for filename in targets:
        try:
            if log_lock is not None:
                log_lock.acquire()
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(result)
                f.flush()
                os.fsync(f.fileno())
            print('[SAVED]', filename)
            saved = True
            break
        except Exception as e:
            print('[ERROR] Failed to save {}: {}'.format(filename, e))
        finally:
            if log_lock is not None:
                log_lock.release()
    if not saved:
        print('WARNING: Could not save, printing below:\n', result)
    return result

def set_process_priority(level):
    try:
        if PSUTIL_AVAILABLE:
            p = psutil.Process(os.getpid())
            if platform.system() == 'Windows':
                m = {
                    'low': psutil.IDLE_PRIORITY_CLASS,
                    'below_normal': psutil.BELOW_NORMAL_PRIORITY_CLASS,
                    'normal': psutil.NORMAL_PRIORITY_CLASS,
                    'above_normal': psutil.ABOVE_NORMAL_PRIORITY_CLASS,
                    'high': psutil.HIGH_PRIORITY_CLASS
                }
                p.nice(m.get(level, psutil.BELOW_NORMAL_PRIORITY_CLASS))
            else:
                m = {'low': 19, 'below_normal': 10, 'normal': 0, 'above_normal': -5, 'high': -10}
                try:
                    p.nice(m.get(level, 10))
                except psutil.AccessDenied:
                    p.nice(0)
        else:
            if platform.system() in ['Linux', 'Darwin']:
                m = {'low': 19, 'below_normal': 10, 'normal': 0}
                val = m.get(level, 10)
                if val > 0:
                    os.nice(val)
    except Exception as e:
        print('Warning: Could not set priority:', e)

def build_bloom_from_database(database_dir, substring_len, bloom_path, error_rate):
    if not BLOOM_AVAILABLE:
        raise RuntimeError('pybloomfiltermmap3 not installed')
    count = 0
    for filename in os.listdir(database_dir):
        fp = os.path.join(database_dir, filename)
        if os.path.isfile(fp):
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    addr = line.strip()
                    if addr and addr.startswith('1') and len(addr) >= substring_len:
                        count += 1
    if count == 0:
        raise RuntimeError('No addresses in database')
    bf = pybloomfilter.BloomFilter(count, error_rate, bloom_path)
    for filename in os.listdir(database_dir):
        fp = os.path.join(database_dir, filename)
        if os.path.isfile(fp):
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    addr = line.strip()
                    if addr and addr.startswith('1') and len(addr) >= substring_len:
                        bf.add(addr[-substring_len:])
    bf.sync()

def open_bloom(bloom_path):
    if not BLOOM_AVAILABLE:
        raise RuntimeError('pybloomfiltermmap3 not installed')
    return pybloomfilter.BloomFilter.open(bloom_path)

def main(bloom_path, args, seed, global_counter, counter_lock, process_id, shutdown_event, log_lock, progress_lock):
    set_process_priority(args['priority'])

    # Open shared Bloom filter (mmap)
    bf = open_bloom(bloom_path)

    keys_processed = 0
    last_save_counter = 0
    start_time = time.time()

    # Windowed duty-cycle CPU limiter (stable and workload-agnostic)
    target = max(1, min(args['cpu_limit'], 100)) / 100.0
    window_s = 0.2  # 200 ms control window
    win_start = time.perf_counter()
    busy = 0.0

    # Optional summary counters for verbose=1
    window_matches = 0
    window_false_pos = 0

    print('Process {}: priority={}, cpu_limit={}%'.format(process_id, args["priority"], args['cpu_limit']))

    try:
        while not shutdown_event.is_set():
            loop_start = time.perf_counter()

            with counter_lock:
                counter = global_counter.value
                global_counter.value += 1

            private_key = generate_private_key_deterministic(seed, counter)
            if private_key is None:
                continue

            public_key = private_key_to_public_key(private_key, args['fastecdsa'])
            if public_key is None:
                continue

            address = public_key_to_address(public_key)
            if address is None:
                continue

            keys_processed += 1

            suffix = address[-args['substring']:]
            if suffix in bf:
                if args['verbose'] >= 2:
                    print('\n[MATCH] Process {}: Verifying...'.format(process_id))
                window_matches += 1
                found = False
                try:
                    for filename in os.listdir(DATABASE_DIR):
                        file_path = os.path.join(DATABASE_DIR, filename)
                        if not os.path.isfile(file_path):
                            continue
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            if address in content:
                                print('\n' + '='*70)
                                print('*** JACKPOT! Process {} ***'.format(process_id))
                                print('='*70)
                                print('Address:', address)
                                print('Counter:', counter)
                                print('='*70)
                                save_found_key(private_key, public_key, address, counter, process_id, log_lock)
                                found = True
                                break
                    if not found:
                        window_false_pos += 1
                        if args['verbose'] >= 2:
                            print('[INFO] False positive, continuing...')
                except Exception as e:
                    if args['verbose'] >= 2:
                        print('Error verifying:', e)

            # CPU limiter accounting
            busy += time.perf_counter() - loop_start
            now = time.perf_counter()
            elapsed = now - win_start
            if elapsed >= window_s:
                # Print summary at verbose=1
                if args['verbose'] == 1 and (window_matches or window_false_pos):
                    print('P{}: matches={} false_pos={}'.format(process_id, window_matches, window_false_pos))
                window_matches = 0
                window_false_pos = 0

                # Enforce duty cycle within the window
                sleep_time = max(0.0, (busy / target) - elapsed)
                if sleep_time > 0:
                    time.sleep(min(sleep_time, 0.05))  # cap to avoid long stalls
                    now = time.perf_counter()
                win_start = now
                busy = 0.0

            # Periodic progress save by a single writer (id==0)
            if process_id == 0 and (counter - last_save_counter >= PROGRESS_SAVE_INTERVAL):
                try:
                    with counter_lock:
                        current_global = global_counter.value
                    save_progress_atomic(seed, current_global, progress_lock)
                    last_save_counter = counter
                    if args['verbose'] >= 2:
                        print('[SAVE] Progress:', current_global)
                except Exception as e:
                    print('Error saving:', e)

    except KeyboardInterrupt:
        print('\nProcess {} interrupted'.format(process_id))
    except Exception as e:
        print('Error in process {}: {}'.format(process_id, e))
        import traceback
        traceback.print_exc()
    finally:
        try:
            with counter_lock:
                final_counter = global_counter.value
            elapsed = time.time() - start_time
            rate = keys_processed / elapsed if elapsed > 0 else 0
            print('Process {}: {} keys at {:.1f} k/s'.format(process_id, keys_processed, rate/1000.0))
        except Exception:
            pass

def signal_handler(signum, frame):
    print('\nShutdown signal received...')
    if shutdown_flag is not None:
        shutdown_flag.set()

def print_help():
    print("""
USAGE:
python3 plutus_stable.py [options]

OPTIONS:
verbose=0/1/2       # 0=silent(jackpots only), 1=window summary, 2=per-match logs
substring=N         # 1..26 (default 8)
cpu_count=N         # default: all cores
cpu_limit=N         # 1..100 (default 80)
priority=LEVEL      # low, below_normal, normal, above_normal, high
reset_seed
build_bloom         # force rebuild of Bloom file
time                # quick speed test
""")
    sys.exit(0)

def timer(args):
    print('\nSpeed test...\n')
    try:
        seed, counter = load_seed_and_counter()
        iterations = 100
        start = time.time()
        for i in range(iterations):
            private_key = generate_private_key_deterministic(seed, counter + i)
            public_key = private_key_to_public_key(private_key, args['fastecdsa'])
            address = public_key_to_address(public_key)
        total_time = time.time() - start
        tpk = total_time / iterations
        print('Iterations:', iterations)
        print('Total time: {:.4f}s'.format(total_time))
        print('Per key: {:.6f}s'.format(tpk))
        print('Keys/sec: {:.2f}'.format(1/tpk))
        print('Sample:', address)
    except Exception as e:
        print('Error:', e)
        import traceback
        traceback.print_exc()
    sys.exit(0)

if __name__ == '__main__':
    args = {
        'verbose': 0,
        'substring': 8,
        'fastecdsa': platform.system() in ['Linux', 'Darwin'],
        'cpu_count': multiprocessing.cpu_count(),
        'cpu_limit': 80,
        'priority': 'below_normal',
    }

    force_build_bloom = False
    reset_seed = False

    for arg in sys.argv[1:]:
        if arg == 'help':
            print_help()
        elif arg == 'time':
            timer(args)
        elif arg == 'reset_seed':
            reset_seed = True
        elif arg == 'build_bloom':
            force_build_bloom = True
        elif '=' in arg:
            cmd, val = arg.split('=', 1)
            if cmd == 'cpu_count':
                try:
                    v = int(val)
                    args['cpu_count'] = max(1, min(v, multiprocessing.cpu_count()))
                except Exception:
                    print('cpu_count must be number'); sys.exit(-1)
            elif cmd == 'cpu_limit':
                try:
                    v = int(val)
                    if 1 <= v <= 100:
                        args['cpu_limit'] = v
                    else:
                        print('cpu_limit: 1-100'); sys.exit(-1)
                except Exception:
                    print('cpu_limit must be number'); sys.exit(-1)
            elif cmd == 'priority':
                if val in ['low', 'below_normal', 'normal', 'above_normal', 'high']:
                    args['priority'] = val
                else:
                    print('priority: low, below_normal, normal, above_normal, high'); sys.exit(-1)
            elif cmd == 'verbose':
                if val in ['0','1','2']:
                    args['verbose'] = int(val)
                else:
                    print('verbose: 0, 1, or 2'); sys.exit(-1)
            elif cmd == 'substring':
                try:
                    sv = int(val)
                    if 1 <= sv <= 26:
                        args['substring'] = sv
                    else:
                        print('substring: 1-26'); sys.exit(-1)
                except Exception:
                    print('substring must be number'); sys.exit(-1)
            else:
                print('Unknown:', cmd); sys.exit(-1)
        else:
            print('Unknown argument:', arg); sys.exit(-1)

    if not BLOOM_AVAILABLE:
        print('Missing dependency: pip install pybloomfiltermmap3')
        sys.exit(-1)

    if reset_seed and os.path.exists(SEED_FILE):
        os.remove(SEED_FILE)
        print('Seed deleted')

    seed, start_counter = load_seed_and_counter()

    # Build or reuse Bloom
    if force_build_bloom or not os.path.exists(BLOOM_FILE):
        if not os.path.isdir(DATABASE_DIR):
            print('[ERROR] Database not found:', DATABASE_DIR)
            sys.exit(-1)
        print('\nBuilding Bloom filter from database...')
        try:
            build_bloom_from_database(DATABASE_DIR, args['substring'], BLOOM_FILE, BLOOM_ERROR_RATE)
            print('[OK] Bloom built at', BLOOM_FILE)
        except Exception as e:
            print('[ERROR] Building bloom:', e)
            sys.exit(-1)
    else:
        print('[OK] Using existing Bloom file:', BLOOM_FILE)

    # Verify Bloom opens
    try:
        bf = open_bloom(BLOOM_FILE)
        del bf
    except Exception as e:
        print('[ERROR] Opening bloom:', e)
        sys.exit(-1)

    print('\nCONFIGURATION')
    print('Substring:', args['substring'])
    print('Processes:', args['cpu_count'])
    print('CPU limit per process:', args['cpu_limit'])
    print('Priority:', args['priority'])
    print('Counter:', start_counter)
    print('Seed file:', SEED_FILE)
    print('Bloom file:', BLOOM_FILE)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        manager = Manager()
        global_counter = manager.Value('i', start_counter)
        counter_lock = manager.Lock()
        log_lock = manager.Lock()
        progress_lock = manager.Lock()
        shutdown_event = manager.Event()
        shutdown_flag = shutdown_event

        processes = []
        print('\nStarting {} processes...\n'.format(args["cpu_count"]))

        for cpu in range(args['cpu_count']):
            p = multiprocessing.Process(
                target=main,
                args=(BLOOM_FILE, args, seed, global_counter, counter_lock, cpu, shutdown_event, log_lock, progress_lock)
            )
            p.start()
            processes.append(p)
            time.sleep(0.05)

        print('Running...\n')

        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            print('\n' + '='*70)
            print('Shutting down...')
            print('='*70)
            shutdown_event.set()
            time.sleep(2)
            for p in processes:
                if p.is_alive():
                    p.terminate()
                p.join(timeout=5)
            try:
                final_counter = global_counter.value
                save_progress_atomic(seed, final_counter, progress_lock)
                print('\n[OK] Saved:', final_counter)
            except Exception as e:
                print('Error saving:', e)
            print('\n[OK] Stopped')

    except Exception as e:
        print('[ERROR]', e)
        import traceback
        traceback.print_exc()
        sys.exit(-1)
