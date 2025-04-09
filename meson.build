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
	'src/model/WebSocketManager.cpp',
	'src/model/FirebaseManager.cpp'
]

crow = dependency('Crow', required: true)
curl_dep = dependency('libcurl', required: true)
jwt = dependency('jwt-cpp', required: true)

deps = [
	crow,
	curl_dep,
	jwt
]

executable('ss', src, dependencies: deps, include_directories: incdir)