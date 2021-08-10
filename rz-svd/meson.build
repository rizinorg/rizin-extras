project('rz-svd', 'c',
  license: 'LGPL3',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
  ]
)

# handle the yxml dependency
plugins_dir = join_paths(get_option('prefix'), 'share', 'rizin', 'plugins')
check_meson_subproject_py = files('sys/check_meson_subproject.py')

py3_exe = import('python').find_installation()

r = run_command(py3_exe, check_meson_subproject_py, 'yxml')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')

rz_core_lib = dependency('rz_core')

library('rz-svd',
  ['rz-svd.c'],
  dependencies: [rz_core_lib, yxml_dep],
  install: true,
  install_dir: plugins_dir,
) 
