import os

# PREFIX = "prefix"
# AddOption('--prefix',dest='prefix',type='string', nargs=1, default='install',
    # action='store', metavar='DIR', help='installation prefix')

env = Environment(tools=['default', 'protoc', 'grpc'])
# def_env = DefaultEnvironment(PREFIX = GetOption('prefix'))

try:
    env.Append(ENV = {'TERM' : os.environ['TERM']}) # Keep our nice terminal environment (like colors ...)
except:
    print "Not running in a terminal"

root_dir = Dir('#').srcnode().abspath
#
config = {}
# config['sse_root_dir'] = Dir('#/..').srcnode().abspath
#
config['cryto_lib_dir'] = root_dir + "/third_party/crypto/library"
config['cryto_include'] = config['cryto_lib_dir']  + "/include"
config['cryto_lib'] = config['cryto_lib_dir']  + "/lib"

config['ssdmap_lib_dir'] = root_dir + "/third_party/ssdmap/library"
config['ssdmap_include'] = config['ssdmap_lib_dir']  + "/include"
config['ssdmap_lib'] = config['ssdmap_lib_dir']  + "/lib"

config['db-parser_lib_dir'] = root_dir + "/third_party/db-parser/library"
config['db-parser_include'] = config['db-parser_lib_dir']  + "/include"
config['db-parser_lib'] = config['db-parser_lib_dir']  + "/lib"
#
# config['dbparser_lib_dir'] = config['sse_root_dir'] + "/db-parser/library"
# config['dbparser_include'] = config['dbparser_lib_dir']  + "/include"
# config['dbparser_lib'] = config['dbparser_lib_dir']  + "/lib"
#
# config['verifiable_containers_lib_dir'] = config['sse_root_dir'] + "/verifiable_containers/library"
# config['verifiable_containers_include'] = config['verifiable_containers_lib_dir']  + "/include"
# config['verifiable_containers_lib'] = config['verifiable_containers_lib_dir']  + "/lib"

# if FindFile('config.scons', '.'):
#     SConscript('config.scons', exports=['env','config'])

env.Append(CCFLAGS = ['-fPIC','-Wall', '-march=native'])
env.Append(CXXFLAGS = ['-std=c++11'])
env.Append(CPPPATH = [config['cryto_include'], config['ssdmap_include'], config['db-parser_include']])
env.Append(LIBPATH = [config['cryto_lib'], config['ssdmap_lib'], config['db-parser_lib']])
env.Append(RPATH = [config['cryto_lib'], config['ssdmap_lib'], config['db-parser_lib']])

env.Append(LIBS = ['crypto', 'sse_crypto', 'ssdmap', 'grpc++_unsecure', 'grpc', 'protobuf', 'pthread', 'dl', 'sse_dbparser', 'rocksdb', 'snappy', 'z', 'bz2',  'lz4'])

#Workaround for OS X
if env['PLATFORM'] == 'darwin':
    rpathprefix = '-rpath'
    env.Append(LINKFLAGS = [[rpathprefix, lib] for lib in env['RPATH']])
    env.Append(CPPPATH=['/usr/local/opt/openssl/include'])
    env.Append(LIBPATH=['/usr/local/opt/openssl/lib'])    
    # env.Append(LINKFLAGS = ['-rpath', cryto_lib_dir+'/lib'])



env['STATIC_AND_SHARED_OBJECTS_ARE_THE_SAME']=1


debug = ARGUMENTS.get('debug', 0)
if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])

env.Append(CPPDEFINES = ['BENCHMARK'])

def run_test(target, source, env):
    app = str(source[0].abspath)
    if os.spawnl(os.P_WAIT, app, app)==0:
        return 0
    else:
        return 1

bld = Builder(action = run_test)
env.Append(BUILDERS = {'Test' :  bld})


crypto_lib_target = env.Command(config['cryto_lib_dir'], "", "cd third_party/crypto && scons lib")
ssdmap_target = env.Command(config['ssdmap_lib_dir'], "", "cd third_party/ssdmap && scons lib")
db_parser_target = env.Command(config['db-parser_lib_dir'], "", "cd third_party/db-parser && scons lib")
env.Alias('deps', [crypto_lib_target, ssdmap_target, db_parser_target])

objects = SConscript('src/build.scons', exports='env', variant_dir='build')
# protos = SConscript('src/protos/build.scons', exports='env', duplicate=0)
# Depends(objects, protos)

env.Depends(objects["diane"],[crypto_lib_target, ssdmap_target, db_parser_target])
env.Depends(objects["sophos"],[crypto_lib_target, ssdmap_target, db_parser_target])

# clean_crypto = env.Command("clean_crypto", "", "cd third_party/crypto && scons -c lib")
# clean_ssdmap = env.Command("clean_ssdmap", "", "cd third_party/ssdmap && scons -c lib")
# env.Alias('clean_deps', [clean_crypto, clean_ssdmap])

Clean(objects["sophos"] + objects["diane"], 'build')

outter_env = env.Clone()
outter_env.Append(CPPPATH = ['build'])


sophos_debug_prog   = outter_env.Program('sophos_debug',    ['test_sophos.cpp']     + objects["sophos"])
sophos_client       = outter_env.Program('sophos_client',   ['sophos_client.cpp']   + objects["sophos"])
sophos_server       = outter_env.Program('sophos_server',   ['sophos_server.cpp']   + objects["sophos"])

diane_debug_prog    = outter_env.Program('diane_debug',     ['test_diane.cpp']      + objects["diane"])
diane_client        = outter_env.Program('diane_client',    ['diane_client.cpp']    + objects["diane"])
diane_server        = outter_env.Program('diane_server',    ['diane_server.cpp']    + objects["diane"])

env.Alias('sophos', [sophos_debug_prog, sophos_client, sophos_server])
env.Alias('diane', [diane_debug_prog, diane_client, diane_server])
env.Default(['diane'])
