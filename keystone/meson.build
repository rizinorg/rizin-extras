project('rizin-keystone', 'cpp')

rz_asm_dep = dependency('rz_asm')

if get_option('plugins_dir') != ''
  plugins_dir = get_option('plugins_dir')
else
  plugins_dir = get_option('prefix') / rz_asm_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_asm_PLUGINDIR')
endif
message('Plugins install directory: ' + plugins_dir)

if get_option('use_sys_keystone')
  keystone_lib = dependency('keystone', allow_fallback: false)
else
  cmake = import('cmake')
  keystone_subproj = cmake.subproject('keystone')
  keystone_lib = keystone_subproj.dependency('keystone')
endif

foreach arch : ['arm', 'hexagon', 'mips', 'ppc', 'sparc', 'sysz', 'x86']
  library('asm_@0@_ks'.format(arch),
    ['asm_@0@_ks.cpp'.format(arch), 'keystone.cpp'],
    dependencies: [rz_asm_dep, keystone_lib],
    install: true,
    install_dir: plugins_dir,
    soversion: rz_asm_dep.version()
  )
endforeach
