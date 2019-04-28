Browsix-Emscripten is Emscripten's fork with support for Browsix. Emscripten version is 1.37.22 is based on Clang/LLVM 4.0. 
To use Emscripten 1.37.22, we need binaryen tools and `fastcomp` 1.37.22. The process to build `fastcomp` 1.37.22 is similar to the instructions mentioned on [here](https://emscripten.org/docs/building_from_source/building_fastcomp_manually_from_source.html).

1. Follow instructions on [here](https://webassembly.org/getting-started/developers-guide/) to install the latest `emsdk`. 
2. Clone `fastcomp` and clang and change the directory to `fastcomp-1.37.22`.
```
git clone https://github.com/emscripten-core/emscripten-fastcomp
cd emsripten-fastcomp
git clone https://github.com/emscripten-core/emscripten-fastcomp-clang tools/clang
cd ..
mv emscripten-fastcomp fastcomp-1.37.22
```
3. Checkout version 1.37.22.
```
cd fastcomp-1.37.22
git checkout 1.37.22
cd tools/clang
git checkout 1.37.22
cd ../..
``` 
5. Create a `build` directory and cd into it.
```
mkdir build
cd build
```
6. Configure and make
```
cmake .. -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="host;JSBackend" -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_INCLUDE_TESTS=OFF -DCLANG_INCLUDE_TESTS=OFF
make -j4
```
7. Open `~/.emscripten` file and set `LLVM_ROOT` to the absolute path of `fastcomp-1.37.22/build/bin` directory.
8. Clone `emscripten` from https://github.com/plasma-umass/browsix-emscripten.git to `emscripten` or extract `emscripten.tar.xz` to `emscripten`.
9. `cd emscripten` and execute `./emcc -v` to run sanity checks. If there any errors (which are usually in red color), then double check the process.

Now we can use emscripten's C compiler `emcc` and C++ compiler `em++` to compile C and C++ to WebAssembly or asm.js using Browsix-WASM. 
