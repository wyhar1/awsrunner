# Series of commands to follow

```bash
rm -rf build
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release
cmake --build build -j 4

source .venv/bin/activate
```
run if needed
```bash
export PM_PK_PATH=/home/ubuntu/pmkey.txt
```
