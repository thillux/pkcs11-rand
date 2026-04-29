project('mini-pkcs11-rand', 'c',
  version          : '0.1.0',
  default_options  : [
    'c_std=c11',
    'warning_level=2',
    'buildtype=debugoptimized',
    'default_library=shared',
    'b_lto=false',
  ],
  meson_version    : '>=0.59.0',
)

cc = meson.get_compiler('c')

# Pool composition: N iso7816 cards + M infnoise devices. Both are
# compile-time constants so the source tree only includes the backend(s)
# that are actually used. The pool layer (src/rng.c) requires N+M >= 1.
n = get_option('iso7816_cards')
m = get_option('infnoise_devices')
pool_size = n + m

if pool_size < 1
  error('Need at least one source: iso7816_cards or infnoise_devices >= 1')
endif

message('RNG pool: iso7816=@0@, infnoise=@1@ (total @2@)'.format(n, m, pool_size))

iso_in = get_option('iso7816_input_bytes')
inf_in = get_option('infnoise_input_bytes')

# SHA3-256 post-processing fires when either:
#   * the pool combines more than one source (N+M > 1), or
#   * any source is oversampled (input_bytes > 32) — in that case the
#     chain is the mechanism that compresses the wide input down to the
#     32-byte output round, and it engages even at N+M=1.
iso_oversampled = n > 0 and iso_in > 32
inf_oversampled = m > 0 and inf_in > 32
use_chain       = pool_size > 1 or iso_oversampled or inf_oversampled

if use_chain
  message('Per-round input: iso7816=@0@ B/card, infnoise=@1@ B/dev (output=32 B/round, SHA3-256 chain)'
          .format(iso_in, inf_in))
else
  message('Single-source raw passthrough (no SHA3-256 chain)')
endif

common_cflags = [
  '-fvisibility=hidden',
  '-Wno-unused-parameter',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  '-D_POSIX_C_SOURCE=200809L',
  '-DISO7816_CARDS=@0@'.format(n),
  '-DINFNOISE_DEVICES=@0@'.format(m),
  '-DISO7816_INPUT_BYTES=@0@'.format(iso_in),
  '-DINFNOISE_INPUT_BYTES=@0@'.format(inf_in),
]

inc = include_directories('include', 'src')

src = ['src/module.c', 'src/rng.c']
deps = [dependency('threads')]

if n > 0
  deps += dependency('libpcsclite', required : true)
  src  += ['src/source_iso7816.c']
endif

if m > 0
  src += ['src/source_infnoise.c', 'src/infnoise-core.c']
endif

if use_chain
  deps += dependency('libcrypto', required : true)
endif

p11rand = shared_library('p11rand',
  sources               : src,
  include_directories   : inc,
  dependencies          : deps,
  c_args                : common_cflags,
  gnu_symbol_visibility : 'hidden',
  install               : true,
  soversion             : '0',
)

dl_dep = cc.find_library('dl', required : true)

p11rand_test = executable('p11rand-test',
  sources             : ['test/p11rand-test.c'],
  include_directories : inc,
  dependencies        : [dl_dep],
  install             : false,
)

p11rand_wait = executable('p11rand-wait',
  sources             : ['tools/p11rand-wait.c'],
  include_directories : inc,
  dependencies        : [dl_dep],
  install             : true,
)

p11rand_seed = executable('p11rand-seed',
  sources             : ['tools/p11rand-seed.c'],
  include_directories : inc,
  dependencies        : [dl_dep],
  install             : true,
)

p11rand_read = executable('p11rand-read',
  sources             : ['tools/p11rand-read.c'],
  include_directories : inc,
  dependencies        : [dl_dep],
  install             : true,
)

# p11rand-list always links both backends so it can inventory every
# PC/SC reader and every FT240X regardless of the .so's pool config.
p11rand_list = executable('p11rand-list',
  sources             : [
    'tools/p11rand-list.c',
    'src/source_iso7816.c',
    'src/source_infnoise.c',
    'src/infnoise-core.c',
  ],
  include_directories : inc,
  dependencies        : [
    dependency('libpcsclite', required : true),
    dependency('threads'),
  ],
  c_args              : ['-D_POSIX_C_SOURCE=200809L'],
  install             : true,
)

test('smoke', p11rand_test, args : [p11rand.full_path()])
