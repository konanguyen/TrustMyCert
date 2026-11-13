import os
import subprocess as sp
import json
import re
import sys
import shutil
import zipfile
from hashlib import sha256

from pathlib import Path
from argparse import ArgumentParser

MODULE_ID = "trustmycert"
MODULE_NAME = "TrustMyCert"
VER_NAME = "1.1.0"

# Build channels:
#   product : stable; only TMC_LOGE is compiled in
#   debug   : troubleshooting; info/warn/error (and debug) logging compiled in
#
# One release ships both channels as separate zips: the debug zip carries
# "-debug" in its file name and module.prop version. `build.py zip` builds
# both. For single-ABI dev commands (build/config/deploy/flash) select the
# channel with DEBUG=1 / DEBUG=0 (or -t debug / -t product); the environment
# variable wins over -t so CI can be explicit. The default is product.
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def parse_bool(value, name="DEBUG"):
    normalized = str(value).strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be 1/0 (or true/false); got {value!r}")


def normalize_build_type(value):
    if value is None:
        return None
    value = value.strip().lower()
    if value == "debug":
        return "debug"
    if value in ("product", "release"):
        return "product"
    raise ValueError(f"unknown build type: {value!r} (expected debug or product)")


def resolve_build_type(args):
    env_debug = os.getenv("DEBUG")
    cli_type = normalize_build_type(args.build_type)

    if env_debug is not None and env_debug.strip() != "":
        build_type = "debug" if parse_bool(env_debug) else "product"
        if cli_type is not None and cli_type != build_type:
            print(f"warning: DEBUG={env_debug} overrides -t {args.build_type}")
        return build_type

    # Local default is product: a plain `build.py build` must never ship a
    # debug library by accident.
    return cli_type or "product"


def normalize_version(value, debug):
    # Both channels of a release share the base version X.Y.Z. The debug zip
    # appends "-debug" so Magisk, the WebUI and file names can never confuse
    # the two. A product version must stay suffix-free.
    version = (value or "").strip()
    if version.startswith("v"):
        version = version[1:]
    if not version:
        version = VER_NAME
    version = re.sub(r"-debug(?:\.\d+)?$", "", version)
    return f"{version}-debug" if debug else version


def version_code_for(debug):
    # Commit count keeps releases monotonic; product outranks a debug build of
    # the same commit, and a newer commit outranks any older release.
    return GIT_COMMIT_COUNT * 1000 + (0 if debug else 999)


def initialize(args):
    global ANDROID_HOME, ANDROID_NDK_HOME, PLATFORM, CMAKE_TOOLCHAIN_FILE, ROOT_DIR, \
        BUILD_DIR, OUTPUT_DIR, SOURCE_DIR, RELEASE_NAME, NATIVE_OUTPUT_DIR, \
        BIN_OUTPUT_DIR, LIB_OUTPUT_DIR, BUILD_TYPE, DEBUG_BUILD, UNSTRIPPED_OUTPUT_DIR, \
        RELEASE_DIR, BUILD_DIR_NAME, CONFIG_VERSION
    ANDROID_HOME = os.getenv('ANDROID_HOME')
    if ANDROID_HOME is None:
        ANDROID_HOME = os.getenv('ANDROID_SDK_ROOT')
    if ANDROID_HOME is None:
        raise ValueError('Please add ANDROID_SDK_ROOT or ANDROID_HOME to your environment variable!')
    ANDROID_HOME = Path(ANDROID_HOME)

    with open('project-config.json', 'r', encoding='utf-8') as f:
        project_config = json.load(f)
        if args.ndk:
            ndk_ver = args.ndk
        else:
            if 'ndkVer' not in project_config:
                raise ValueError('ndkVer not exist!')
            ndk_ver = project_config['ndkVer']
            if ndk_ver == '':
                raise ValueError('ndkVer should not be empty!')
        ANDROID_NDK_HOME = ANDROID_HOME / 'ndk' / ndk_ver
        if not os.path.isdir(ANDROID_NDK_HOME):
            raise ValueError(f'Ndk {ndk_ver} not exist: {ANDROID_NDK_HOME}')
        if 'platform' not in project_config:
            raise ValueError('platform not exist!')
        PLATFORM = project_config['platform']
        CONFIG_VERSION = project_config.get('version', VER_NAME)

    CMAKE_TOOLCHAIN_FILE = ANDROID_NDK_HOME / 'build/cmake/android.toolchain.cmake'
    BUILD_TYPE = resolve_build_type(args)
    DEBUG_BUILD = BUILD_TYPE == "debug"
    ROOT_DIR = Path(__file__).parent.resolve()
    BUILD_DIR = (ROOT_DIR / "my_build").absolute()
    OUTPUT_DIR = (ROOT_DIR / "output").absolute()
    BUILD_DIR_NAME = BUILD_TYPE
    NATIVE_OUTPUT_DIR = OUTPUT_DIR / "native" / BUILD_DIR_NAME
    BIN_OUTPUT_DIR = NATIVE_OUTPUT_DIR / "bin"
    LIB_OUTPUT_DIR = NATIVE_OUTPUT_DIR / "lib"
    UNSTRIPPED_OUTPUT_DIR = OUTPUT_DIR / "unstripped" / BUILD_DIR_NAME
    RELEASE_DIR = ROOT_DIR / "release"
    SOURCE_DIR = ROOT_DIR / "native"
    RELEASE_NAME = normalize_version(os.getenv("TMC_VERSION", CONFIG_VERSION), DEBUG_BUILD)


def exec_out(cmd):
    p = sp.Popen(cmd, stdout=sp.PIPE)
    content = p.stdout.read().decode('utf-8').strip()
    p.wait()
    return content


def exec_cmd(cmd, ignore_error=False, *args, **kwargs):
    p = sp.Popen(cmd, *args, **kwargs)
    v = p.wait()
    if not ignore_error and v != 0:
        raise RuntimeError(f'exec return non-zero: {v} {cmd}')


def exec_adb_cmd(c, device=None, *args, **kwargs):
    cmd = ['adb']
    if device is not None:
        cmd += ['-s', device]
    cmd += c
    exec_cmd(cmd, *args, **kwargs)


def exec_adb_shell(c, device=None, root=False, *args, **kwargs):
    cmd = ['adb']
    if device is not None:
        cmd += ['-s', device]
    cmd += ['shell']
    if root:
        cmd += [f'exec su -c \'{c}\'']
    else:
        cmd += [c]
    exec_cmd(cmd, *args, **kwargs)

GIT_COMMIT_COUNT = int(exec_out('git rev-list HEAD --count'.split(' ')))
GIT_COMMIT_HASH = exec_out('git rev-parse --verify --short HEAD'.split(' '))


def config(abi, plat, build_type):
    bin_build_type = BUILD_TYPE_CHOICES_MAP[build_type]
    build_dir = BUILD_DIR / BUILD_DIR_NAME / abi
    lib_output_dir = LIB_OUTPUT_DIR / abi
    bin_output_dir = BIN_OUTPUT_DIR / abi
    unstripped_output_dir = UNSTRIPPED_OUTPUT_DIR / abi
    exec_cmd(
        [
            'cmake',
            f'-H{SOURCE_DIR}',
            f'-B{build_dir}',
            f'-DANDROID_ABI={abi}',
            f'-DANDROID_PLATFORM={plat}',
            f'-DANDROID_NDK={ANDROID_NDK_HOME}',
            '-DANDROID_STL=c++_static',
            '-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON',
            f'-DCMAKE_TOOLCHAIN_FILE={CMAKE_TOOLCHAIN_FILE}',
            f'-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={bin_output_dir}',
            f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={lib_output_dir}',
            f'-DDEBUG_SYMBOLS_PATH={unstripped_output_dir}',
            f"-DCMAKE_BUILD_TYPE={bin_build_type}",
            f"-DTMC_DEBUG_BUILD={'1' if DEBUG_BUILD else '0'}",
            f"-DMODULE_NAME={MODULE_ID}",
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
            '-G', 'Ninja'
        ]
    )


def build_target(target, abi, plat, build_type):
    build_dir = BUILD_DIR / BUILD_DIR_NAME / abi
    config(abi, plat, build_type=build_type)
    exec_cmd(['cmake', "--build", build_dir, "--", target, f'-j{os.cpu_count()}'])
    # TODO: return bin output
    return None

def build_all(abi, plat, build_type, force):
    lib_output_dir = LIB_OUTPUT_DIR / abi
    bin_output_dir = BIN_OUTPUT_DIR / abi
    if force:
        shutil.rmtree(lib_output_dir, ignore_errors=True)
        shutil.rmtree(bin_output_dir, ignore_errors=True)
        shutil.rmtree(UNSTRIPPED_OUTPUT_DIR / abi, ignore_errors=True)
    build_dir = BUILD_DIR / BUILD_DIR_NAME / abi
    config(abi, plat, build_type=build_type)
    exec_cmd(['cmake', "--build", build_dir, "--", f'-j{os.cpu_count()}'])


def get_device_abi(device):
    cmd = ['adb']
    if device is not None:
        cmd += ['-s', device]
    cmd += ['shell', 'getprop ro.product.cpu.abi']
    return exec_out(cmd)


SUPPORTED_ABIS = ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86', 'riscv64']


def deploy(target, device, abi, dest, build_type):
    if abi is None:
        abi = get_device_abi(device)
    if abi not in SUPPORTED_ABIS:
        raise ValueError(f'device has unsupported abi: {abi}')
    print('** Deploying', abi)
    output = build_target(target, abi, PLATFORM, build_type=build_type)
    exec_adb_cmd(['push', output, dest], device=device)
    exec_adb_cmd(['shell', f'chmod +x {dest}/{target}'], device=device)
    print(f'Deploy {target} to {dest}/{target}')


ABI_NAME_ALIAS = {
    'arm64-v8a': ['arm64', 'a64', 'aarch64', 'arm64_v8a'],
    'armeabi-v7a': ['armeabi', 'arm', 'arm32', 'a32', 'armeabi_v7a'],
    'x86': ['i386', 'x32'],
    'x86_64': ['x64', 'x86-64'],
    'riscv64': ['riscv']
}
ABI_CHOICES = list(ABI_NAME_ALIAS.keys()) + sum(ABI_NAME_ALIAS.values(), [])
ABI_MAP = {None: None}
def initialize_abi_alias():
    for k in ABI_NAME_ALIAS:
        ABI_MAP[k] = k
        for v in ABI_NAME_ALIAS[k]:
            ABI_MAP[v] = k
initialize_abi_alias()
DEFAULT_ABI = "arm64-v8a"
ABI_TO_ARCH = {
    'arm64-v8a': 'aarch64',
    'armeabi-v7a': 'arm',
    'x86_64': 'x86_64',
    'x86': 'i386',
    'riscv64': 'riscv64',
}
# https://topjohnwu.github.io/Magisk/guides.html#variables
ABI_TO_MAGISK_ARCH = {
    'arm64-v8a': 'arm64',
    'armeabi-v7a': 'arm',
    'x86_64': 'x64',
    'x86': 'x86',
    'riscv64': 'riscv64',
}
BUILD_TYPE_CHOICES = ["debug", "product"]
BUILD_TYPE_CHOICES_MAP = {
    "debug": "Debug",
    "product": "RelWithDebInfo"
}


def build_cmd(args):
    if args.target is None:
        build_all(
            abi=ABI_MAP[args.abi], plat=PLATFORM, build_type=BUILD_TYPE, force=args.force
        )
    else:
        build_target(args.target, abi=ABI_MAP[args.abi], plat=PLATFORM, build_type=BUILD_TYPE)


def config_cmd(args):
    config(ABI_MAP[args.abi], plat=PLATFORM, build_type=BUILD_TYPE)


def deploy_cmd(args):
    deploy(args.target, args.device, abi=ABI_MAP[args.abi], dest=args.dest, build_type=BUILD_TYPE)


def clean_cmd(args):
    abi = '*'
    if args.abi is not None:
        abi = ABI_MAP[args.abi]
    build_type = '*'
    if args.build_type is not None:
        build_type = normalize_build_type(args.build_type)
    for p in Path.glob(BUILD_DIR, f'{build_type}/{abi}'):
        print('Cleaning', p)
        shutil.rmtree(p)


def _select_channel(build_type):
    """Point every output path and the version string at one channel."""
    global BUILD_TYPE, DEBUG_BUILD, BUILD_DIR_NAME, NATIVE_OUTPUT_DIR, \
        BIN_OUTPUT_DIR, LIB_OUTPUT_DIR, UNSTRIPPED_OUTPUT_DIR, RELEASE_NAME
    BUILD_TYPE = build_type
    DEBUG_BUILD = build_type == "debug"
    BUILD_DIR_NAME = build_type
    NATIVE_OUTPUT_DIR = OUTPUT_DIR / "native" / BUILD_DIR_NAME
    BIN_OUTPUT_DIR = NATIVE_OUTPUT_DIR / "bin"
    LIB_OUTPUT_DIR = NATIVE_OUTPUT_DIR / "lib"
    UNSTRIPPED_OUTPUT_DIR = OUTPUT_DIR / "unstripped" / BUILD_DIR_NAME
    RELEASE_NAME = normalize_version(os.getenv("TMC_VERSION", CONFIG_VERSION), DEBUG_BUILD)


def build_channel_zip(args):
    """Build every ABI for the selected channel and package the module zip."""
    for abi in SUPPORTED_ABIS:
        build_all(
            abi=abi, plat=PLATFORM, build_type=BUILD_TYPE, force=args.force
        )

    module_path = OUTPUT_DIR / "module" / BUILD_DIR_NAME
    module_source = ROOT_DIR / 'module'
    shutil.rmtree(module_path, ignore_errors=True)
    os.makedirs(module_path, exist_ok=True)

    # prepare files
    def fix_crlf(p: Path):
        with open(p, 'r', encoding='utf-8') as f:
            text = f.read()
            text = text.replace('\r', '').encode('utf-8')
        with open(p, 'wb') as f:
            f.write(text)

    def expand_text_file(p: Path, expand=None):
        if not p.exists():
            return
        with open(p, 'r', encoding='utf-8') as f:
            text = f.read()
            if expand:
                for k in expand:
                    v = expand[k]
                    text = text.replace(f'@{k}@', v)
                    text = text.replace(f'${{{k}}}', v)
        with open(p, 'wb') as f:
            f.write(text.encode('utf-8'))

    shutil.copytree(module_source, module_path, dirs_exist_ok=True)
    shutil.copy(ROOT_DIR / 'README.md', module_path / 'README.md')

    for p, _, fns in module_path.walk():
        for fn in fns:
            if fn == 'mazoku':
                continue
            fix_crlf(p / fn)
    expand_text_file(module_path / 'module.prop', {
        'moduleId': MODULE_ID,
        'moduleName': MODULE_NAME,
        'versionName': RELEASE_NAME,
        'versionCode': str(version_code_for(DEBUG_BUILD)),
        'buildType': BUILD_TYPE,
    })
    script_vars = {
        'DEBUG': '1' if DEBUG_BUILD else '0',
        'SONAME': MODULE_ID,
        'SUPPORTED_ABIS': ' '.join(map(lambda x: ABI_TO_MAGISK_ARCH[x], SUPPORTED_ABIS))
    }
    expand_text_file(module_path / 'customize.sh', script_vars)
    expand_text_file(module_path / 'post-fs-data.sh', script_vars)
    expand_text_file(module_path / 'service.sh', script_vars)
    expand_text_file(module_path / 'uninstall.sh', script_vars)
    expand_text_file(module_path / 'cleanup.sh', script_vars)

    # filter empty lines and comments
    with open(module_path / 'sepolicy.rule', 'r', encoding='utf-8') as f:
        content = f.read()
    with open(module_path / 'sepolicy.rule', 'w', encoding='utf-8') as f:
        f.write('\n'.join(filter(lambda x:not (x.strip().startswith('#') or x.strip() == ''), content.split('\n'))) + '\n')

    shutil.copytree(NATIVE_OUTPUT_DIR, module_path, dirs_exist_ok=True)

    # build zip
    build_name = f'{MODULE_NAME}-{RELEASE_NAME}-{GIT_COMMIT_HASH}'
    zip_file_name = f"{build_name}.zip".replace(' ', '-')
    output_path = RELEASE_DIR / zip_file_name
    os.makedirs(output_path.parent, exist_ok=True)

    try:
        os.remove(output_path)
    except FileNotFoundError:
        pass

    with zipfile.ZipFile(output_path, 'w', compression=zipfile.ZIP_DEFLATED) as out_zip:
        for p, dns, fns in module_path.walk():
            for dn in dns:
                d = p / dn
                rp = str(d.relative_to(module_path)).replace('\\', '/')
                out_zip.mkdir(rp)
            for fn in fns:
                f = p / fn
                rp = str(f.relative_to(module_path)).replace('\\', '/')
                s = sha256()
                with open(f, 'rb') as fp:
                    with out_zip.open(rp, 'w') as wf:
                        while data := fp.read(4096):
                            s.update(data)
                            wf.write(data)
                s = s.digest()
                with out_zip.open(rp + '.sha256', 'w') as wf:
                    wf.write(s.hex().encode('utf-8'))

    print(f"* output {output_path}")

    if args.save_debug:
        symbols_name = f"{build_name}-symbols.zip".replace(' ', '-')
        symbols_out = ROOT_DIR / "symbols" / symbols_name
        os.makedirs(symbols_out.parent, exist_ok=True)
        with zipfile.ZipFile(symbols_out, 'w', compression=zipfile.ZIP_DEFLATED) as out_zip:
            for p, dns, fns in UNSTRIPPED_OUTPUT_DIR.walk():
                for dn in dns:
                    d = p / dn
                    rp = str(d.relative_to(UNSTRIPPED_OUTPUT_DIR)).replace('\\', '/')
                    out_zip.mkdir(rp)
                for fn in fns:
                    f = p / fn
                    rp = str(f.relative_to(UNSTRIPPED_OUTPUT_DIR)).replace('\\', '/')
                    with open(f, 'rb') as fp:
                        data = fp.read()
                    with out_zip.open(rp, 'w') as wf:
                        wf.write(data)
        print(f"* symbols {symbols_out}")

    return output_path


def build_zip(args):
    # One invocation packages both channels: the release ships
    # TrustMyCert-<version>-<hash>.zip (product) plus the same zip with
    # "-debug" in the name for the debug channel.
    outputs = []
    for build_type in ("debug", "product"):
        _select_channel(build_type)
        print(f"** Building {BUILD_TYPE} channel ({RELEASE_NAME})")
        outputs.append(build_channel_zip(args))
    return outputs


def zip_cmd(args):
    build_zip(args)


def flash(args):
    if args.skip:
        candidates = [
            p for p in RELEASE_DIR.glob("*.zip")
            if RELEASE_NAME in p.name and (("-debug" in p.name) == DEBUG_BUILD)
        ]
        if not candidates:
            raise FileNotFoundError(f"no {BUILD_TYPE} zip for {RELEASE_NAME} in {RELEASE_DIR}")
        zip_file = max(candidates, key=os.path.getmtime)
    else:
        # build_zip packages both channels; flash the one selected by DEBUG/-t.
        candidates = [p for p in build_zip(args) if ("-debug" in p.name) == DEBUG_BUILD]
        zip_file = candidates[0]
    print('use zip file', zip_file)
    root = args.root
    if root is None:
        root = ''
    else:
        root = root.lower()
    name = os.path.basename(zip_file)
    exec_adb_cmd(['push', zip_file, f'/data/local/tmp/{name}'], device=args.device)
    exec_adb_cmd(['push', ROOT_DIR / "scripts/install_module.sh", "/data/local/tmp/install_module.sh"], device=args.device)
    exec_adb_shell(f"sh /data/local/tmp/install_module.sh /data/local/tmp/{name}", device=args.device, root=True)
    exec_adb_shell(f"rm /data/local/tmp/install_module.sh /data/local/tmp/{name}", device=args.device, root=True, ignore_error=True)
    if args.reboot:
        exec_adb_shell("svc power reboot || reboot", device=args.device, root=True, ignore_error=True)


def main():
    ap = ArgumentParser(
        prog="build",
        description=""
    )
    ap.add_argument('--ndk', dest='ndk', required=False, help="ndk")
    ap.add_argument('--save-debug', dest='save_debug', action='store_true')
    ap.add_argument('--force', dest='force', help="build without cache", action='store_true')
    ap.add_argument(
        '-t', dest='build_type', choices=BUILD_TYPE_CHOICES, default=None,
        help="channel for build/config/deploy/flash (default: product, or DEBUG env; zip builds both)"
    )

    subps = ap.add_subparsers(required=True)

    build_args = subps.add_parser('build')
    build_args.add_argument('target', nargs='?')
    build_args.add_argument('-a', dest='abi', choices=ABI_CHOICES, default=DEFAULT_ABI)
    build_args.set_defaults(func=build_cmd)

    config_args = subps.add_parser('config')
    config_args.set_defaults(func=config_cmd)
    config_args.add_argument('-a', dest='abi', choices=ABI_CHOICES, default=DEFAULT_ABI)

    deploy_args = subps.add_parser('deploy')
    deploy_args.add_argument('target')
    deploy_args.set_defaults(func=deploy_cmd)
    deploy_args.add_argument('-s', dest='device', required=False)
    deploy_args.add_argument('-a', dest='abi', choices=ABI_CHOICES, default=None)
    deploy_args.add_argument('-d', dest='dest', default='/data/local/tmp')

    clean_args = subps.add_parser('clean')
    clean_args.add_argument('-a', '--abi', default=None)
    clean_args.set_defaults(func=clean_cmd)

    zip_args = subps.add_parser('zip')
    zip_args.set_defaults(func=zip_cmd)

    flash_args = subps.add_parser('flash')
    flash_args.add_argument('-s', '--device', dest='device', required=False)
    flash_args.add_argument('--root', dest='root', required=False)
    flash_args.add_argument('-r', '--reboot', dest='reboot', action='store_true')
    flash_args.add_argument('--skip', dest='skip', action='store_true')
    flash_args.set_defaults(func=flash)

    args = ap.parse_args(sys.argv[1:])
    initialize(args)
    args.func(args)


main()
