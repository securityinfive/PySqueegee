# move the imports to each function if only used there?
import json, psutil, winreg, platform, socket, uuid, os, getpass, re, subprocess, platform, GPUtil, sys
from datetime import datetime
from tabulate import tabulate
from pprint import pprint

def print_header(header):
    print("="*75)
    print(header)
    print("="*75)
    
def cpu_read():
    print("="*20, " CPU")
    cpu = psutil.cpu_times()
    print(cpu)
    #hold = psutil.disk_usage("/")
    #print(hold)
    #user = psutil.users()
    #print(user)
    
def get_services():
    print_header("SERVICES")
    print("="*20, " SERVICES")
    svcs = list(psutil.win_service_iter())
    pprint(svcs)
      
def get_platform():
    print_header("PLATFORM INFO")
    """     print("="*20, " PLATFORM INFO")
    print(platform.architecture())
    print(platform.machine())
    print(platform.processor())
    print(platform.release())
    print(platform.system())
    print(platform.uname())
    print(platform.version())
    print(platform.win32_edition()) """

    # JSON
    info={}
    info['platform']=platform.system()
    info['platform-release']=platform.release()
    info['platform-version']=platform.version()
    info['architecture']=platform.machine()
    info['hostname']=socket.gethostname()
    info['ip-address']=socket.gethostbyname(socket.gethostname())
    info['mac-address']=':'.join(re.findall('..', '%012x' % uuid.getnode()))
    info['processor']=platform.processor()
    info['ram']=str(round(psutil.virtual_memory().total / (1024.0 **3)))+" GB"
    
    print(tabulate(info.items(), headers=["Name", "Value"]))

def win_registry():
    print_header("SERVICES")
    
    # Registry
    # winreg
    # \HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    # \HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    # \HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall

    reg_HKLM = r"HKEY_LOCAL_MACHINE"
    reg_HKCU = r"HKEY_CURRENT_USER"
    
    reg_run = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    reg_apps = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

    #connecting to key in registry
    read_reg(reg_HKLM, reg_run)
    read_reg(reg_HKCU, reg_run)
    
    # This one needs to loop through the subkeys
    # read_reg(reg_HKLM, reg_apps)

def read_reg(reg_choice, reg_choice2):
    # this will work where the keys are in the root of the target you are hitting, need a subkey enumberator for others
    reg_ok = 0
    reg_key = ""
    print(reg_choice, reg_choice2)
    if reg_choice == "HKEY_CURRENT_USER" and reg_choice2 is not None:
        access_registry = winreg.ConnectRegistry(None,winreg.HKEY_CURRENT_USER)
        reg_key = reg_choice2
        reg_ok += 1
    elif reg_choice == "HKEY_LOCAL_MACHINE" and reg_choice2 is not None:
        access_registry = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)
        reg_key = reg_choice2
        reg_ok += 1
    else:
        print("Invalid registry value.")
    
    if reg_ok == 1:
        access_key = winreg.OpenKey(access_registry, reg_key)
        #accessing the key to open the registry directories under
        try:
            reg_info = {}
            i = 0
            while 1:
                # Not understadning how the line below works... ?
                name, value, type = winreg.EnumValue(access_key, i)
                reg_info[name] = value
                #print(name, value)
                i += 1
        except WindowsError as e:
            # Cleaner error, 259 = No more items, anything else bad. 
            if e.winerror == 259:
                print()
            else:
                print(e.strerror)

    print(tabulate(reg_info.items(), headers=["App Name", "Path"]))
    print("~"*40)

def get_installed_apps():
    print_header("INSTALLED APPS")
    # importing the module 
   
    # traverse the software list 
    Data = subprocess.check_output(['wmic', 'product', 'get', 'name']) 
    a = str(Data) 
    
    # try block 
    try: 
        
        # arrange the string 
        for i in range(len(a)): 
            print(a.split("\\r\\r\\n")[6:][i]) 
    
    except IndexError as e: 
        print("All Done")

def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

def get_os():
    print_header("OS INFO")

    # Last Boot Time
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)
    print(f"Last Boot Time: {bt.month}/{bt.day}/{bt.year} {bt.hour}:{bt.minute}:{bt.second}")
    
    # Windws %PATH%
    system_path = os.getenv('PATH')
    system_path = system_path.split(";")
    print()
    print("WINDOWS PATH ENVIRONMENT VARIABLES")
    print("-"*40)
    for directory in system_path:
        print(directory)
    print()

    print("-"*40)
    print("CURRENT CPU(s) USE")
    print("-"*40)
    # number of cores
    cpufreq = psutil.cpu_freq()
    cpu_list = {}
    cpu_list["Total Cores"] = psutil.cpu_count(logical=True)  
    cpu_list["# Physcial Cores"] = psutil.cpu_count(logical=False)    
    cpu_list["Max. Frequency"] = str(cpufreq.max) + "Mhz"    
    cpu_list["Min. Frequency"] = str(cpufreq.min) + "Mhz"
    cpu_list["Current Frequency"] = str(cpufreq.current) + "Mhz"
    print(tabulate(cpu_list.items(), headers=["INFO", "VALUE"]))
    print()
   
    print("-"*40)
    print("CURRENT MEMORY USE")
    print("-"*40)
    # get the memory details
    svmem = psutil.virtual_memory()
    svmem_list = {}
    svmem_list["Total"] = get_size(svmem.total)
    svmem_list["Free"] = get_size(svmem.available)
    svmem_list["Used"] = get_size(svmem.used)
    svmem_list["Percentage"] = str(svmem.percent) + "%"
    print(tabulate(svmem_list.items(), headers=["INFO", "VALUE"]))
    print()

    print("-"*40)
    print("SWAP MEMORY")
    print("-"*40)
    # get the swap memory details (if exists)
    swap = psutil.swap_memory()
    swap_list = {}
    swap_list["Total"] = get_size(swap.total)
    swap_list["Free"] = get_size(swap.free)
    swap_list["Used"] = get_size(swap.used)
    swap_list["Percentage"] = str(swap.percent) + "%"
    print(tabulate(swap_list.items(), headers=["INFO", "VALUE"]))
    print()
      
def get_disk():
    print("="*20, " DISK INFO")
    print("="*40, "Disk Information", "="*40)
    print("Partitions and Usage:")
    # get all disk partitions
    partitions = psutil.disk_partitions()
    for partition in partitions:
        print(f"=== Device: {partition.device} ===")
        print(f"  Mountpoint: {partition.mountpoint}")
        print(f"  File system type: {partition.fstype}")
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            # this can be catched due to the disk that
            # isn't ready
            continue
        print(f"  Total Size: {get_size(partition_usage.total)}")
        print(f"  Used: {get_size(partition_usage.used)}")
        print(f"  Free: {get_size(partition_usage.free)}")
        print(f"  Used %: {partition_usage.percent}%")
    # get IO statistics since boot
    disk_io = psutil.disk_io_counters()
    print(f"  Total read: {get_size(disk_io.read_bytes)}")
    print(f"  Total write: {get_size(disk_io.write_bytes)}")

def get_network():
    print("="*40, "Network Information", "="*40)
    # get all network interfaces (virtual and physical)
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                print(f"=== Interface: {interface_name} ===")
                print(f"  IP Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast IP: {address.broadcast}")
            elif str(address.family) == 'AddressFamily.AF_PACKET':
                print(f"=== Interface: {interface_name} ===")
                print(f"  MAC Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast MAC: {address.broadcast}")
    # get IO statistics since boot
    net_io = psutil.net_io_counters()
    print("="*20, " NETWORK TRAFFIC SINCE LAST BOOT")
    print(f"  Total Sent: {get_size(net_io.bytes_sent)}")
    print(f"  Total Received: {get_size(net_io.bytes_recv)}")

def get_gpu():
    print("="*20, " GPU Details (NVIDIA ONLY)")
    gpus = GPUtil.getGPUs()
    if gpus != []:
        list_gpus = []
        for gpu in gpus:
            # get the GPU id
            gpu_id = gpu.id
            # name of GPU
            gpu_name = gpu.name
            # get % percentage of GPU usage of that GPU
            gpu_load = f"{gpu.load*100}%"
            # get free memory in MB format
            gpu_free_memory = f"{gpu.memoryFree}MB"
            # get used memory
            gpu_used_memory = f"{gpu.memoryUsed}MB"
            # get total memory
            gpu_total_memory = f"{gpu.memoryTotal}MB"
            # get GPU temperature in Celsius
            gpu_temperature = f"{gpu.temperature} °C"
            gpu_uuid = gpu.uuid
            list_gpus.append((
                gpu_id, gpu_name, gpu_load, gpu_free_memory, gpu_used_memory,
                gpu_total_memory, gpu_temperature, gpu_uuid
            ))

        print(tabulate(list_gpus, headers=("id", "name", "load", "free memory", "used memory", "total memory",
                                        "temperature", "uuid")))
    else:
        print("NVIDIA GPU not present.")


def get_running_processes():
    print("="*40, " CURRENT RUNNING PROCESSES")
    proc_list = []
    for proc in psutil.process_iter():
        try:
            proc_list.append((proc.name(), proc.pid, get_size(proc.memory_info().vms), proc.status()))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    print(tabulate(sorted(proc_list), headers=("Process Name" , "PID", "Memory", "Status")))
    print("="*40, " END CURRENT RUNNING PROCESSES")

def get_env_var():
    print("="*20, " ENVIRONMENT VARIABLES")
    sys_hold = os.getenv('HOMEDRIVE')
    print(sys_hold)
    sys_hold = os.getenv('PathExt')
    print(sys_hold)
    sys_hold = os.getenv('SystemDrive')
    print(sys_hold)
    sys_hold = os.getenv('SystemRoot')
    print(sys_hold)
    sys_hold = os.getenv('USERDOMAIN')
    print(sys_hold)
    sys_hold = os.getenv('COMPUTERNAME')
    print(sys_hold)
    sys_hold = os.getenv('OS')
    print(sys_hold)

def main():
    #cpu_read()
    #win_registry()
    #get_platform()
    #get_installed_apps()
    #get_os()
    get_disk()
    #get_network()
    #get_gpu() # NVIDIA ONLY
    #get_running_processes()
    #get_env_var()


if __name__ == "__main__":
    print("Hello and welcome.")
    print("It's time to check your system.")
    main()


# try to write a dynamic tabulate print function, pass in the headers and the data. 