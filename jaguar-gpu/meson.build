project('jaguar-gpu', 'c')

plugins_dir = join_paths(get_option('prefix'), 'share', 'rizin', 'plugins')

rz_asm_lib = dependency('rz_asm')

library('jaguar-gpu',
  ['jaguar-gpu.c'],
  dependencies: [rz_asm_lib],
  install: true,
  install_dir: plugins_dir,
) 
