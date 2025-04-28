project(
	'Stun Server', 
	'c', 
    default_options : ['c_std=c11']
)

incdir = include_directories('src/include')

src = [
  'src/main.c',
  'src/model/Utils.c',
  'src/model/WebSocketManager.c'
]

libwebsockets = dependency('libwebsockets', required: true)
cjson = declare_dependency(
  include_directories: include_directories('/usr/include'),
  link_args: ['-lcjson']
)

deps = [
    libwebsockets,
    cjson
]

executable('cs', src, dependencies: deps, include_directories: incdir)