# Enable CodeQL for ViDeZZo

This document shows how to use CodeQL to extract annotation information from
QEMU (currently only QEMU is supported) source code.

## Steps 

1 Prepare CodeQL CLI

```
mkdir codeql-home && cd codeql-home

# in codeql-home
rm -f codeql-linux64.zip
wget https://github.com/github/codeql-cli-binaries/releases/download/v2.11.1/codeql-linux64.zip
unzip codeql-linux64.zip

export PATH=path/to/codeql-home/codeql:$PATH
codeql --help
```

2 Obtain a local copy of the CodeQL queries

```
# in codeql-home
git clone https://github.com/github/codeql.git codeql-repo
cp -r path/to/videzzo/annotation/ViDeZZo /path/to/codeql-home/codeql-repo/cpp/ql/src/
```

3 Create a CodeQL database

```
# in codeql-home
git clone https://github.com/qemu/qemu.git --depth=1 codeql-qemu
cd codeql-qemu
codeql database create videzzo-v3 --language=cpp --command=/path/to/videzzo/annotation/codeql-build-qemu.sh -j8
# here we have the database in codeql-home/codeql-qemu/videzzo-v3
```

4 Run CodeQL queries

```
# in codeql-home
codeql query run codeql-qemu/videzzo-v3 -- codeql-repo/cpp/ql/src/ViDeZZo/
```

Please also check [Analyzing your projects in
VSCode](https://codeql.github.com/docs/codeql-for-visual-studio-code/analyzing-your-projects/).
With VSCode, we can check where the results are in the source code and have a
look at the AST nodes.
