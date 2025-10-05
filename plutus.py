#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Plutus Bitcoin Brute Forcer - CPU Limited Version v2
# Fixed: save_progress() error handling

from fastecdsa import keys, curve
from ellipticcurve.privateKey import PrivateKey
import platform
import multiprocessing
from multiprocessing import Value, Lock, Manager
import hashlib
import binascii
import os
import sys
import time
import signal

# Try to import psutil for CPU management (optional)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. CPU limiting features will be restricted.")
    print("Install with: pip install psutil")

DATABASE = r'database/latest/'  
SEED_FILE = 'plutus_seed.txt'
PROGRESS_SAVE_INTERVAL = 1000000
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

shutdown_flag = None

def create_new_seed():
    """Create a new random seed file"""
    try:
        seed = binascii.hexlify(os.urandom(32)).decode('utf-8').upper()
        with open(SEED_FILE, 'w', encoding='utf-8') as f:
            f.write('seed: {}\n'.format(seed))
            f.write('counter: 0\n')
            f.write('created: {}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S")))
        print('Created new seed file: {}'.format(SEED_FILE))
        print('Seed: {}'.format(seed))
        return seed, 0
    except Exception as e:
        print('Error creating seed file: {}'.format(e))
        sys.exit(-1)

def load_seed_and_counter():
    """Load seed and counter from file"""
    seed, counter = None, 0
    try:
        if os.path.exists(SEED_FILE):
            with open(SEED_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line.startswith('seed:'):
                        seed = line.split(':', 1)[1].strip()
                    elif line.startswith('counter:'):
                        counter = int(line.split(':', 1)[1].strip())
            if seed is None or len(seed) != 64:
                raise ValueError("Invalid seed format")
            int(seed, 16)
            print('Loaded existing seed file: {}'.format(SEED_FILE))
            print('Seed: {}'.format(seed))
            print('Starting from counter: {:,}'.format(counter))
        else:
            seed, counter = create_new_seed()
    except (ValueError, FileNotFoundError) as e:
        print('Error loading seed file: {}'.format(e))
        print('Creating new seed file...')
        seed, counter = create_new_seed()
    except Exception as e:
        print('Unexpected error loading seed file: {}'.format(e))
        sys.exit(-1)
    return seed, counter

def save_progress(seed, counter):
    """Save current progress atomically with improved error handling"""
    temp_file = SEED_FILE + '.tmp'
    try:
        # Ghi vào temp file với encoding rõ ràng
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write('seed: {}\n'.format(seed))
            f.write('counter: {}\n'.format(counter))
            f.write('updated: {}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S")))
            f.flush()
            os.fsync(f.fileno())  # Đảm bảo data ghi xuống disk

        # Verify temp file được tạo thành công
        if not os.path.exists(temp_file):
            raise IOError("Temp file was not created: {}".format(temp_file))

        # Sử dụng os.replace() thay vì os.rename()
        # os.replace() atomic và hoạt động tốt trên cả Windows/Linux
        # Nó sẽ overwrite file đích nếu đã tồn tại
        os.replace(temp_file, SEED_FILE)

    except Exception as e:
        print('Error saving progress: {}'.format(e))
        print('Current directory: {}'.format(os.getcwd()))
        print('Temp file exists: {}'.format(os.path.exists(temp_file)))
        # Cleanup temp file nếu nó tồn tại
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
                print('Cleaned up temp file')
            except Exception as cleanup_error:
                print('Failed to cleanup temp file: {}'.format(cleanup_error))

def generate_private_key_deterministic(seed, counter):
    """Generate deterministic private key"""
    try:
        seed_bytes = bytes.fromhex(seed)
        counter_bytes = counter.to_bytes(32, byteorder='big')
        combined = seed_bytes + counter_bytes
        hash_result = hashlib.sha256(combined).digest()
        private_int = int.from_bytes(hash_result, byteorder='big')
        if private_int == 0 or private_int >= SECP256K1_ORDER:
            private_int = (private_int % (SECP256K1_ORDER - 1)) + 1
        private_key = '{:064X}'.format(private_int)
        if len(private_key) != 64:
            raise ValueError("Invalid private key length: {}".format(len(private_key)))
        return private_key
    except Exception as e:
        print('Error generating private key: {}'.format(e))
        return None

def private_key_to_public_key(private_key, fastecdsa):
    """Convert private key to public key"""
    try:
        if not private_key or len(private_key) != 64:
            raise ValueError("Invalid private key format")
        int(private_key, 16)
        if fastecdsa:
            key = keys.get_public_key(int('0x' + private_key, 0), curve.secp256k1)
            public_key = '04' + (hex(key.x)[2:] + hex(key.y)[2:]).zfill(128)
        else:
            pk = PrivateKey().fromString(bytes.fromhex(private_key))
            public_key = '04' + pk.publicKey().toString().hex().upper()
        if len(public_key) != 130 or not public_key.startswith('04'):
            raise ValueError("Invalid public key")
        return public_key
    except Exception as e:
        print('Error converting to public key: {}'.format(e))
        return None

def public_key_to_address(public_key):
    """Convert public key to Bitcoin address"""
    try:
        if not public_key or len(public_key) != 130 or not public_key.startswith('04'):
            raise ValueError("Invalid public key format")
        int(public_key, 16)
        output = []
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        var = hashlib.new('ripemd160')
        encoding = binascii.unhexlify(public_key.encode())
        var.update(hashlib.sha256(encoding).digest())
        var_encoded = ('00' + var.hexdigest()).encode()
        digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
        var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
        count = [char != '0' for char in var_hex].index(True) // 2
        n = int(var_hex, 16)
        while n > 0:
            n, remainder = divmod(n, 58)
            output.append(alphabet[remainder])
        for i in range(count): 
            output.append(alphabet[0])
        address = ''.join(output[::-1])
        if not address or not address.startswith('1'):
            raise ValueError("Invalid Bitcoin address")
        if len(address) < 26 or len(address) > 35:
            raise ValueError("Invalid address length: {}".format(len(address)))
        return address
    except Exception as e:
        print('Error converting to address: {}'.format(e))
        return None

def private_key_to_wif(private_key):
    """Convert private key to WIF format"""
    try:
        if not private_key or len(private_key) != 64:
            raise ValueError("Invalid private key format")
        int(private_key, 16)
        digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
        var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
        var = binascii.unhexlify('80' + private_key + var[0:8])
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        value = pad = 0
        result = ''
        for i, c in enumerate(var[::-1]): 
            value += 256**i * c
        while value >= len(alphabet):
            div, mod = divmod(value, len(alphabet))
            result, value = alphabet[mod] + result, div
        result = alphabet[value] + result
        for c in var:
            if c == 0: 
                pad += 1
            else: 
                break
        wif = alphabet[0] * pad + result
        if len(wif) < 50 or len(wif) > 52:
            raise ValueError("Invalid WIF length: {}".format(len(wif)))
        return wif
    except Exception as e:
        print('Error converting to WIF: {}'.format(e))
        return None

def save_found_key(private_key, public_key, address, counter, process_id):
    """Save found key with multiple backups"""
    wif_key = private_key_to_wif(private_key)
    if not wif_key:
        wif_key = "ERROR_GENERATING_WIF"
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

    save_attempts = [
        'plutus.txt',
        'plutus_backup_{}.txt'.format(int(time.time())),
        'found_key_{}_{}.txt'.format(counter, process_id)
    ]
    saved = False
    for filename in save_attempts:
        try:
            with open(filename, 'a') as f:
                f.write(result)
                f.flush()
                os.fsync(f.fileno())
            print('[SAVED] {}'.format(filename))
            saved = True
            break
        except Exception as e:
            print('[ERROR] Failed to save {}: {}'.format(filename, e))
    if not saved:
        print('\n' + '!'*70)
        print('WARNING: Could not save! COPY THIS DATA:')
        print('!'*70)
        print(result)
        print('!'*70)
    return result

def set_process_priority(priority_level):
    """Set process priority"""
    try:
        if PSUTIL_AVAILABLE:
            p = psutil.Process(os.getpid())
            if platform.system() == 'Windows':
                priority_map = {
                    'low': psutil.IDLE_PRIORITY_CLASS,
                    'below_normal': psutil.BELOW_NORMAL_PRIORITY_CLASS,
                    'normal': psutil.NORMAL_PRIORITY_CLASS,
                    'above_normal': psutil.ABOVE_NORMAL_PRIORITY_CLASS,
                    'high': psutil.HIGH_PRIORITY_CLASS
                }
                p.nice(priority_map.get(priority_level, psutil.BELOW_NORMAL_PRIORITY_CLASS))
            else:
                nice_map = {
                    'low': 19,
                    'below_normal': 10,
                    'normal': 0,
                    'above_normal': -5,
                    'high': -10
                }
                nice_value = nice_map.get(priority_level, 10)
                try:
                    p.nice(nice_value)
                except psutil.AccessDenied:
                    if nice_value < 0:
                        print('Warning: Cannot set high priority (requires root)')
                        p.nice(0)
        else:
            if platform.system() in ['Linux', 'Darwin']:
                nice_map = {'low': 19, 'below_normal': 10, 'normal': 0}
                nice_value = nice_map.get(priority_level, 10)
                if nice_value > 0:
                    os.nice(nice_value)
    except Exception as e:
        print('Warning: Could not set priority: {}'.format(e))

def main(database, args, seed, global_counter, counter_lock, process_id, shutdown_event):
    """Main loop with EFFECTIVE CPU limiting"""

    set_process_priority(args['priority'])

    keys_processed = 0
    last_save_counter = 0
    start_time = time.time()

    # Calculate sleep time for CPU limiting
    cpu_limit = args['cpu_limit']
    if cpu_limit < 100:
        keys_per_batch = max(1, int(cpu_limit / 10))
        sleep_per_batch = (100 - cpu_limit) / cpu_limit * 0.01
    else:
        keys_per_batch = 100
        sleep_per_batch = 0

    print('Process {}: priority={}, cpu_limit={}%'.format(process_id, args["priority"], cpu_limit))
    if cpu_limit < 100:
        print('Process {}: Will process {} keys then sleep {:.4f}s'.format(
            process_id, keys_per_batch, sleep_per_batch))

    try:
        batch_count = 0
        while not shutdown_event.is_set():
            with counter_lock:
                counter = global_counter.value
                global_counter.value += 1

            if keys_processed % 100 == 0 and shutdown_event.is_set():
                break

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
            batch_count += 1

            if args['verbose'] and keys_processed % 100 == 0:
                elapsed = time.time() - start_time
                rate = keys_processed / elapsed if elapsed > 0 else 0
                print('P{}: {} | {:,} | {:.1f} k/s'.format(
                    process_id, address, counter, rate))

            if address[-args['substring']:] in database:
                print('\n[MATCH] Process {}: Verifying...'.format(process_id))
                found_match = False
                try:
                    for filename in os.listdir(DATABASE):
                        file_path = os.path.join(DATABASE, filename)
                        if not os.path.isfile(file_path):
                            continue
                        try:
                            with open(file_path, 'r') as file:
                                content = file.read()
                                if address in content:
                                    print('\n' + '='*70)
                                    print('*** JACKPOT! Process {} ***'.format(process_id))
                                    print('='*70)
                                    print('Address: {}'.format(address))
                                    print('Counter: {:,}'.format(counter))
                                    print('='*70)
                                    save_found_key(private_key, public_key, address, counter, process_id)
                                    found_match = True
                                    break
                        except Exception as e:
                            print('Error reading {}: {}'.format(filename, e))
                    if not found_match:
                        print('[INFO] False positive, continuing...')
                except Exception as e:
                    print('Error verifying: {}'.format(e))

            if cpu_limit < 100 and batch_count >= keys_per_batch:
                time.sleep(sleep_per_batch)
                batch_count = 0

            if counter - last_save_counter >= PROGRESS_SAVE_INTERVAL:
                try:
                    with counter_lock:
                        current_global = global_counter.value
                    save_progress(seed, current_global)
                    last_save_counter = counter
                    if args['verbose']:
                        print('[SAVE] Progress: {:,}'.format(current_global))
                except Exception as e:
                    print('Error saving: {}'.format(e))

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
            print('Process {}: {:,} keys at {:.1f} k/s'.format(
                process_id, keys_processed, rate))
        except:
            pass

def signal_handler(signum, frame):
    """Handle signals"""
    print('\n\nShutdown signal received...')
    if shutdown_flag is not None:
        shutdown_flag.set()

def print_help():
    print("""
===============================================================================
Plutus Bitcoin Brute Forcer - CPU Limited Version v2 (FIXED)
===============================================================================

USAGE:
python3 plutus_cpu_limited_fixed_v2.py [options]

OPTIONS:
verbose=0/1         Show addresses (default: 0)
substring=N         Match last N chars (default: 8, range: 1-26)
cpu_count=N         Number of processes (default: all cores)
cpu_limit=N         CPU limit % (default: 80, range: 1-100)
priority=LEVEL      Priority: low, below_normal, normal (default: below_normal)
reset_seed          Start with new seed

EXAMPLES:
python3 plutus_cpu_limited_fixed_v2.py                      # 80% CPU
python3 plutus_cpu_limited_fixed_v2.py cpu_limit=30         # 30% CPU
python3 plutus_cpu_limited_fixed_v2.py cpu_limit=50 cpu_count=2

FIXES IN V2:
- Fixed save_progress() error with os.replace()
- Better error handling and debugging
- Improved file write atomicity

NOTES:
- Install psutil for better CPU control: pip install psutil
- Database folder: database/latest/
""")
    sys.exit(0)

def timer(args):
    """Speed test"""
    print('\nSpeed test...\n')
    try:
        seed, counter = load_seed_and_counter()
        iterations = 100
        start = time.time()
        for i in range(iterations):
            private_key = generate_private_key_deterministic(seed, counter + i)
            public_key = private_key_to_public_key(private_key, args['fastecdsa'])
            address = public_key_to_address(public_key)
        end = time.time()
        total_time = end - start
        time_per_key = total_time / iterations
        print('Iterations: {}'.format(iterations))
        print('Total time: {:.4f}s'.format(total_time))
        print('Per key: {:.6f}s'.format(time_per_key))
        print('Keys/sec: {:.2f}'.format(1/time_per_key))
        print('\nSample: {}'.format(address))
        if private_key and public_key and address:
            print('\n[OK] Working correctly')
        else:
            print('\n[ERROR] Has issues')
        total_addresses = 2**160
        time_for_all = (total_addresses * time_per_key) / (60 * 60 * 24 * 365.25)
        print('\nTime for all 2^160: {:.2e} years'.format(time_for_all))
    except Exception as e:
        print('Error: {}'.format(e))
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

    reset_seed = False

    for arg in sys.argv[1:]:
        if arg == 'help':
            print_help()
        elif arg == 'time':
            timer(args)
        elif arg == 'reset_seed':
            reset_seed = True
        elif '=' in arg:
            command, value = arg.split('=', 1)
            if command == 'cpu_count':
                try:
                    cpu_count = int(value)
                    if 1 <= cpu_count <= multiprocessing.cpu_count():
                        args['cpu_count'] = cpu_count
                    else:
                        print('cpu_count: 1-{}'.format(multiprocessing.cpu_count()))
                        sys.exit(-1)
                except ValueError:
                    print('cpu_count must be number')
                    sys.exit(-1)
            elif command == 'cpu_limit':
                try:
                    cpu_limit = int(value)
                    if 1 <= cpu_limit <= 100:
                        args['cpu_limit'] = cpu_limit
                    else:
                        print('cpu_limit: 1-100')
                        sys.exit(-1)
                except ValueError:
                    print('cpu_limit must be number')
                    sys.exit(-1)
            elif command == 'priority':
                if value in ['low', 'below_normal', 'normal', 'above_normal', 'high']:
                    args['priority'] = value
                else:
                    print('priority: low, below_normal, normal, above_normal, high')
                    sys.exit(-1)
            elif command == 'verbose':
                if value in ['0', '1']:
                    args['verbose'] = int(value)
                else:
                    print('verbose: 0 or 1')
                    sys.exit(-1)
            elif command == 'substring':
                try:
                    substring = int(value)
                    if 1 <= substring <= 26:
                        args['substring'] = substring
                    else:
                        print('substring: 1-26')
                        sys.exit(-1)
                except ValueError:
                    print('substring must be number')
                    sys.exit(-1)
            else:
                print('Unknown: {}'.format(command))
                sys.exit(-1)
        else:
            print('Unknown argument: {}'.format(arg))
            sys.exit(-1)

    if reset_seed and os.path.exists(SEED_FILE):
        os.remove(SEED_FILE)
        print('Seed deleted')

    seed, start_counter = load_seed_and_counter()

    print('\nLoading database...')
    database = set()
    database_loaded = False
    try:
        if not os.path.exists(DATABASE):
            print('[ERROR] Database not found: {}'.format(DATABASE))
            sys.exit(-1)
        file_count = 0
        for filename in os.listdir(DATABASE):
            file_path = os.path.join(DATABASE, filename)
            if not os.path.isfile(file_path):
                continue
            try:
                with open(file_path, 'r') as file:
                    for address in file:
                        address = address.strip()
                        if address and address.startswith('1') and len(address) >= args['substring']:
                            database.add(address[-args['substring']:])
                file_count += 1
            except Exception as e:
                print('Warning: {}: {}'.format(filename, e))
        if file_count == 0:
            print('[ERROR] No database files')
            sys.exit(-1)
        if len(database) == 0:
            print('[ERROR] No addresses in database')
            sys.exit(-1)
        database_loaded = True

        print('[OK] Database loaded\n')
        print('=' * 70)
        print('CONFIGURATION:')
        print('=' * 70)
        print('Database: {:,} suffixes'.format(len(database)))
        print('Files: {}'.format(file_count))
        print('Substring: {} chars'.format(args["substring"]))
        print('Processes: {}'.format(args["cpu_count"]))
        print('CPU limit: {}% per process'.format(args["cpu_limit"]))
        print('Priority: {}'.format(args["priority"]))
        print('Counter: {:,}'.format(start_counter))
        print('Save interval: {:,} keys'.format(PROGRESS_SAVE_INTERVAL))
        print('=' * 70)

        if args['cpu_limit'] < 100:
            total_estimated = args['cpu_count'] * args['cpu_limit']
            print('\nEstimated total CPU: ~{}%'.format(total_estimated))
            print('(= {} processes x {}% each)'.format(args["cpu_count"], args["cpu_limit"]))

        if not PSUTIL_AVAILABLE:
            print('\nNote: Install psutil for better CPU control')
            print('  pip install psutil')

        print('\nPress Ctrl+C to stop\n')
        time.sleep(2)

    except Exception as e:
        print('[ERROR] Loading database: {}'.format(e))
        import traceback
        traceback.print_exc()
        sys.exit(-1)

    if not database_loaded:
        print('[ERROR] Database failed')
        sys.exit(-1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        manager = Manager()
        global_counter = manager.Value('i', start_counter)
        counter_lock = manager.Lock()
        shutdown_event = manager.Event()
        shutdown_flag = shutdown_event

        processes = []
        print('Starting {} processes...\n'.format(args["cpu_count"]))

        for cpu in range(args['cpu_count']):
            p = multiprocessing.Process(
                target=main, 
                args=(database, args, seed, global_counter, counter_lock, cpu, shutdown_event)
            )
            p.start()
            processes.append(p)
            time.sleep(0.1)

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
                save_progress(seed, final_counter)
                print('\n[OK] Saved: {:,}'.format(final_counter))
            except Exception as e:
                print('Error saving: {}'.format(e))
            print('\n[OK] Stopped')

    except Exception as e:
        print('[ERROR] {}'.format(e))
        import traceback
        traceback.print_exc()
        sys.exit(-1)
