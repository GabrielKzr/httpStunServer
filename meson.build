project(
	'Stun Server', 
	'cpp', 
	default_options : ['cpp_std=c++20']
)

incdir = include_directories('src/include')

src = [
	'src/main.cpp', 
	'src/StunServer.cpp',
	'src/model/Utils.cpp',
	'src/model/WebSocketManager.cpp'
]

crow = dependency('Crow')

deps = [
	crow
]

executable('ss', src, dependencies: deps, include_directories: incdir)