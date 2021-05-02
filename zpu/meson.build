project('zpu.c', 'c')

plugins_dir = join_paths(get_option('prefix'), 'share', 'rizin', 'plugins')

rz_asm_lib = dependency('rz_asm')

library('zpu',
  ['zpu.c'],
  dependencies: [rz_asm_lib],
  install: true,
  install_dir: plugins_dir,
) 
