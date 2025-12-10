# 버전관리

# 1.0.0 
  > - 25-12-10 14:49
  > - 84437139a2b8b9d2b8df27c01ef13acd0378c1a4 
- 전체적인 파일 디렉토리 생성
- WinRM 연결테스트 python 생성 및 성공 (scripts/winrm_test.py)

```linux
┌──(kali㉿kali)-[~/openedr_v1/scripts]
└─$ python3 winrm_test.py 

=== WinRM 연결 테스트 ===
Target IP: 192.168.200.104   
Username: edradmin
Password: 
[+] Endpoint: http://192.168.200.104:5985/wsman
[+] 연결 테스트 중...
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
hostname: DESKTOP-0N915IG

whoami: desktop-0n915ig\edradmin

[+] WinRM 연결 성공!

```
