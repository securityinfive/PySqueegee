# move the imports to each function if only used there?
import psutil 
import winreg
import platform
import socket
import uuid
import os
import re
import subprocess
import GPUtil

from datetime import datetime
from tabulate import tabulate
from pprint import pprint

def print_header(header):
    print("="*75)
    print(header)
    print("="*75)    

def write_header(header, report_name):
    write_report("\n", report_name)
    write_report("~"*70, report_name)
    write_report("\n" + header + "\n", report_name)
    write_report("~"*70, report_name)
    write_report("\n", report_name)

def get_platform(report_name):
    print_header("PLATFORM INFO")
    
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

    write_header("PLATFORM INFO", report_name)
    write_report(tabulate(info.items(), headers=["Name", "Value"]), report_name)
    #write_report("\n", report_name)

def get_os(report_name):
    print_header("OS INFO")
    
    # Last Boot Time
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)
    print(f"Last Boot Time: {bt.month}/{bt.day}/{bt.year} {bt.hour}:{bt.minute}:{bt.second}")
    write_report("\n\nLast Boot Time : " + str(bt) + "\n", report_name)
    

    # Windws %PATH%
    system_path = os.getenv('PATH')
    system_path = system_path.split(";")
    print()
    print("WINDOWS PATH ENVIRONMENT VARIABLES")
    print("-"*40)
    
    write_header("WINDOWS PATH ENVIRONMENT VARIABLES", report_name)
    #write_report("\nWINDOWS PATH ENVIRONMENT VARIABLES\n", report_name)
    #write_report("~"*40 + "\n", report_name)
    
    for directory in system_path:
        print(directory)
        write_report(directory + "\n", report_name)
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

    write_header("CURRENT CPU(s) USE", report_name)
    #write_report("~"*40, report_name) # The Path loop above adds \n, don't need to do one again here.
    #write_report("\nCURRENT CPU(s) USE", report_name)
    #write_report("\n" + "~"*40 + "\n", report_name)
    write_report(tabulate(cpu_list.items(), headers=["INFO", "VALUE"]), report_name)
    write_report("\n", report_name)

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

    write_header("CURRENT MEMORY USE", report_name)
    #write_report("~"*40, report_name)
    #write_report("\nCURRENT MEMORY USE\n", report_name)
    #write_report("~"*40, report_name)
    write_report(tabulate(svmem_list.items(), headers=["INFO", "VALUE"]), report_name)
    write_report("\n", report_name)

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

    write_header("SWAP  MEMORY", report_name)
    #write_report("~"*40, report_name)
    #write_report("\nSWAP MEMORY\n", report_name)
    #write_report("~"*40, report_name)
    #write_report("\n", report_name)
    write_report(tabulate(swap_list.items(), headers=["INFO", "VALUE"]), report_name)
    write_report("\n", report_name)

def cpu_read(report_name):
    print("="*20, " CPU")
    cpu = psutil.cpu_times()
    print(cpu)
    #hold = psutil.disk_usage("/")
    #print(hold)
    #user = psutil.users()
    #print(user)
    
def get_services(report_name):
    print_header("RUNNING SERVICES")
    write_header("RUNNING SERVICES", report_name)

    svc_dis_name = ""
    svc_startup = ""
    svc_descr = ""
    svc_status = ""
    svc_bin = ""

    svcs = list(psutil.win_service_iter())

    for svc in svcs:
        svc_info = psutil.win_service_get(svc.name()).as_dict()
        svc_data = {}
        for svc_key, svc_item in svc_info.items():
            if svc_info['status'] == 'running':
                match svc_key:
                    case 'display_name':
                        svc_dis_name = svc_item
                        svc_data["Display Name"] = svc_item
                    case 'binpath':
                        svc_bin = svc_item
                    case 'start_type':
                        svc_startup = svc_item
                        svc_data["Startup"] = svc_item
                    case 'description':
                        svc_descr = svc_item
                        svc_data["Description"] = svc_item
                    case 'status':
                        svc_status = svc_item

        print(f"Name - ", svc_dis_name)
        print(f"Binpath - ", svc_bin)
        print(f"Startup - ", svc_startup)
        print(f"Status - ", svc_status)
        print(f"Description - ", svc_descr)
        print("#"*70)
        
        write_report("Name - " + svc_dis_name, report_name)
        write_report("\nBinpath - " + svc_bin, report_name)
        write_report("\nStartup - " + svc_startup, report_name)
        write_report("\nStatus - " + svc_status, report_name)
        write_report("\nDescription - " + str(svc_descr), report_name)
        write_report("\n" + "-"*50, report_name)
        write_report("\n", report_name)

def win_registry(report_name):
    print_header("START UP APPS")
    write_header("STARTUP APPS")
    
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

def get_time():
    now_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return(now_time)

def write_report(writeline, report_name):
    report_name.write(writeline)
    
def main():
    write_report('\n\nScans started.\n', report_file)
    
    #get_platform(report_file)
    #get_os(report_file)
    #get_services(report_file)
    #cpu_read(report_file)
    win_registry(report_file)
    #get_installed_apps()
    #get_disk()
    #get_network()
    #get_gpu() # NVIDIA ONLY
    #get_running_processes()
    #get_env_var()
    report_file.close()
    
if __name__ == "__main__":
    now_time = get_time()
    report_time = now_time.replace(':' , '')

    print(r"""
    ______      _____                                       
    | ___ \    /  ___|                                      
    | |_/ /   _\ `--.  __ _ _   _  ___  ___  __ _  ___  ___ 
    |  __/ | | |`--. \/ _` | | | |/ _ \/ _ \/ _` |/ _ \/ _ \
    | |  | |_| /\__/ / (_| | |_| |  __/  __/ (_| |  __/  __/
    \_|   \__, \____/ \__, |\__,_|\___|\___|\__, |\___|\___|
           __/ |         | |                 __/ |          
          |___/          |_|                |___/           
          """)
    print(report_time, '-', "PySqueegee scans starting.")
    print("Report file : PySqueegee ", report_time + '.txt')

    filename = 'PySqueegee ' + report_time + '.txt'
    report_file = open(filename, 'w', encoding="utf-8")
    report_file.write(r"""
    ______      _____                                       
    | ___ \    /  ___|                                      
    | |_/ /   _\ `--.  __ _ _   _  ___  ___  __ _  ___  ___ 
    |  __/ | | |`--. \/ _` | | | |/ _ \/ _ \/ _` |/ _ \/ _ \
    | |  | |_| /\__/ / (_| | |_| |  __/  __/ (_| |  __/  __/
    \_|   \__, \____/ \__, |\__,_|\___|\___|\__, |\___|\___|
           __/ |         | |                 __/ |          
          |___/          |_|                |___/           
          """)                      

    main()