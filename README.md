# Zygisk Module Template

A Zygisk Module Template based on zygisk-module-sample.

It's suggested to use VSCode for development.

## Build

```bash
# generate compile_commands.json
python build.py config [-a abi]
# build module zip
python build.py zip
# build and flash module zip
python build.py flash [--reboot]
```

The zip will be output to `release` .

## Development environment

- LLVM clangd  
- VSCode + Clangd Plugin  
- Android NDK  
- CMake  

## See also

https://github.com/topjohnwu/zygisk-module-sample
