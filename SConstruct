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
env.Append(CPPPATH = [config['cryto_include'], config['ssdmap_include']])
env.Append(LIBPATH = [config['cryto_lib'], config['ssdmap_lib']])
env.Append(RPATH = [config['cryto_lib'], config['ssdmap_lib']])

env.Append(LIBS = ['crypto', 'sse_crypto', 'ssdmap', 'grpc++_unsecure', 'grpc', 'protobuf', 'pthread', 'dl'])

#Workaround for OS X
if env['PLATFORM'] == 'darwin':
    rpathprefix = '-rpath'
    env.Append(LINKFLAGS = [[rpathprefix, lib] for lib in env['RPATH']])
    # env.Append(LINKFLAGS = ['-rpath', cryto_lib_dir+'/lib'])



env['STATIC_AND_SHARED_OBJECTS_ARE_THE_SAME']=1


debug = ARGUMENTS.get('debug', 0)
if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])


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
env.Alias('deps', [crypto_lib_target, ssdmap_target])

objects = SConscript('src/build.scons', exports='env', variant_dir='build')
# protos = SConscript('src/protos/build.scons', exports='env', duplicate=0)
# Depends(objects, protos)

env.Depends(objects,[crypto_lib_target, ssdmap_target])

# clean_crypto = env.Command("clean_crypto", "", "cd third_party/crypto && scons -c lib")
# clean_ssdmap = env.Command("clean_ssdmap", "", "cd third_party/ssdmap && scons -c lib")
# env.Alias('clean_deps', [clean_crypto, clean_ssdmap])

Clean(objects, 'build')

debug_prog = env.Program('debug',['main.cpp'] + objects, CPPPATH = ['src'] + env.get('CPPPATH', []))
client = env.Program('client',['client_main.cpp'] + objects, CPPPATH = ['build'] + env.get('CPPPATH', []))
server = env.Program('server',['server_main.cpp'] + objects, CPPPATH = ['build'] + env.get('CPPPATH', []))

env.Default([debug_prog, client, server])

# check_env = env.Clone()
#
# tmp_env = Environment()
#
# if not check_env.GetOption('clean'):
#     conf = Configure(tmp_env)
#     if conf.CheckLib('boost_unit_test_framework'):
#         print 'Found boost unit test framework'
#
#         check_env.Append(LIBS = ['boost_unit_test_framework'])
#
#         test_prog = check_env.Program('check', ['checks.cpp'] + objects + test_objects)
#         test_run = check_env.Test('test_run', test_prog)
#         Depends(test_run, test_prog)
#         check_env.Alias('check', [test_prog, test_run])
#
#     else:
#         print 'boost unit test framework not found'
#         print 'Skipping checks. Be careful!'
#     tmp_env = conf.Finish()
#
# check_env.Clean('check', ['check'] + objects)
