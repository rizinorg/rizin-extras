project('jaguar-gpu', 'c')

rz_asm_dep = dependency('rz_asm')
plugins_dir = get_option('prefix') / rz_asm_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_asm_PLUGINDIR')
message('Plugins install directory: ' + plugins_dir)

library('jaguar-gpu',
  ['jaguar-gpu.c'],
  dependencies: [rz_asm_dep],
  install: true,
  install_dir: plugins_dir,
)
