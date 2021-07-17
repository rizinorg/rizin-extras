project('rz-svd', 'c')

plugins_dir = join_paths(get_option('prefix'), 'share', 'rizin', 'plugins')

rz_core_lib = dependency('rz_core')

library('rz-svd',
  ['rz-svd.c'],
  dependencies: [rz_core_lib],
  install: true,
  install_dir: plugins_dir,
) 
