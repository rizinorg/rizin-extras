project('kvx', 'c')

rz_asm_dep = dependency('rz_asm')
rz_analysis_dep = dependency('rz_analysis')
rizin_plugdir = get_option('rizin_plugdir')
if rizin_plugdir == ''
  plugins_dir = rz_asm_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_asm_PLUGINDIR')
endif
message('Plugins install directory: ' + plugins_dir)

library('kvx_asm',
  ['kvx-reg.c', 'kvx-dis.c', 'kvx_asm.c'],
  dependencies: [rz_asm_dep],
  install: true,
  install_dir: plugins_dir,
)

library('kvx_analysis',
  ['kvx-reg.c', 'kvx-dis.c', 'kvx_analysis.c'],
  dependencies: [rz_analysis_dep],
  install: true,
  install_dir: plugins_dir,
)
