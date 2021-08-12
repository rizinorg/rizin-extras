project('rz-svd', 'c',
  version: '0.1.0',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ]
)

# handle the yxml dependency
plugins_dir = join_paths(get_option('prefix'), 'share', 'rizin', 'plugins')

py3_exe = import('python').find_installation()

yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')

rz_core_lib = dependency('rz_core')

library('rz-svd',
  ['rz-svd.c'],
  dependencies: [rz_core_lib, yxml_dep],
  install: true,
  install_dir: plugins_dir,
) 
