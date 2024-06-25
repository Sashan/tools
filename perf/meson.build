project('perf', 'c',
  version : '0.1',
  default_options : ['warning_level=0'])

pymodule = import('python3')
python3 = pymodule.find_python()

res = run_command(python3, '-c', 'import os; print(os.environ["OPENSSL_PATH"])')
if res.returncode() == 0
  openssl_path = res.stdout().strip('\n')
else 
  # not found, do fallback
endif

libperf_srcs = [
	'./perflib/perfhelper.c',
	'./perflib/perfsslhelper.c',
	'./perflib/threads.c',
	'./perflib/time.c'
]


header_path = openssl_path + 'include'
lib_path = openssl_path + 'lib'
libperf = static_library('perf', libperf_srcs, include_directories : [ header_path ])
openssl_dep = declare_dependency(
        dependencies : dependency('threads'),
	link_args : [ '-L' + lib_path, '-lssl', '-lcrypto' ],
	include_directories : [ header_path ]
)

executable('evp_fetch', 'evp_fetch.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('randbytes', 'randbytes.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('handshake', 'handshake.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('sslnew', 'sslnew.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('newrawkey', 'newrawkey.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('rsasign', 'rsasign.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('x509storeissuer', 'x509storeissuer.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('providerdoall', 'providerdoall.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('rwlocks', 'rwlocks.c', link_with : libperf, dependencies : [ openssl_dep ])
executable('pkeyread', 'pkeyread.c', link_with : libperf, dependencies : [ openssl_dep ])
