var BrowsixLibrary = {
  $BROWSIX__deps: [
#if EMTERPRETIFY_ASYNC
    '$EmterpreterAsync', 'fflush', 'memcpy',
#endif
#if SYSCALL_DEBUG
    '$ERRNO_MESSAGES',
#endif
    '$ENV',
  ],
  $BROWSIX: {
    browsix: (function() {
      var exports = {};

      exports.async = true;
      exports.waitOff = -1;
      exports.syncMsg = {};

      exports.SHM_SIZE = {{{ BROWSIX_SHM_SIZE }}};
      exports.shm = null;
      exports.shmU8 = null;
      exports.shm8 = null;
      exports.shm32 = null;
      exports.SHM_OFF = 128;
      exports.SHM_BUF_SIZE = {{{ BROWSIX_SHM_SIZE - 128 }}};

      exports.getShmLen = function(len) {
        return (len > BROWSIX.browsix.SHM_BUF_SIZE) ? BROWSIX.browsix.SHM_BUF_SIZE : len;
      };

      exports.getShmLenAt = function(off, len) {
        return (off + len > BROWSIX.browsix.SHM_BUF_SIZE) ? BROWSIX.browsix.SHM_BUF_SIZE - off : len;
      };

      // copy a zero-terminated (C) string to our shared buffer
      exports.putShmString = function(off, ptr) {
        let shmU8 = BROWSIX.browsix.shmU8;
        let i = 0;
        for (i = 0; i < BROWSIX.browsix.SHM_BUF_SIZE; i++) {
          shmU8[off + i] = HEAPU8[ptr + i];
          if (HEAPU8[ptr+i] === 0)
            break;
        }
        return off + i + 1;
      };

      exports.copyFromUser = function(dest, src, num) {
        dest = dest|0; src = src|0; num = num|0;
        var SHM8 = BROWSIX.browsix.shm8;
        var SHM32 = BROWSIX.browsix.shm32;
        var ret = 0;
        var aligned_dest_end = 0;
        var block_aligned_dest_end = 0;
        var dest_end = 0;
        // Test against a benchmarked cutoff limit for when HEAPU8.set() becomes faster to use.
        if ((num|0) >=
          8192
        ) {
          return BROWSIX.browsix.copyFromUserBig(dest|0, src|0, num|0)|0;
        }

        ret = dest|0;
        dest_end = (dest + num)|0;
        if ((dest&3) == (src&3)) {
          // The initial unaligned < 4-byte front.
          while (dest & 3) {
            if ((num|0) == 0) return ret|0;
            SHM8[((dest)>>0)]=((HEAP8[((src)>>0)])|0);
            dest = (dest+1)|0;
            src = (src+1)|0;
            num = (num-1)|0;
          }
          aligned_dest_end = (dest_end & -4)|0;
          block_aligned_dest_end = (aligned_dest_end - 64)|0;
          while ((dest|0) <= (block_aligned_dest_end|0) ) {
            SHM32[((dest)>>2)]=((HEAP32[((src)>>2)])|0);
            SHM32[(((dest)+(4))>>2)]=((HEAP32[(((src)+(4))>>2)])|0);
            SHM32[(((dest)+(8))>>2)]=((HEAP32[(((src)+(8))>>2)])|0);
            SHM32[(((dest)+(12))>>2)]=((HEAP32[(((src)+(12))>>2)])|0);
            SHM32[(((dest)+(16))>>2)]=((HEAP32[(((src)+(16))>>2)])|0);
            SHM32[(((dest)+(20))>>2)]=((HEAP32[(((src)+(20))>>2)])|0);
            SHM32[(((dest)+(24))>>2)]=((HEAP32[(((src)+(24))>>2)])|0);
            SHM32[(((dest)+(28))>>2)]=((HEAP32[(((src)+(28))>>2)])|0);
            SHM32[(((dest)+(32))>>2)]=((HEAP32[(((src)+(32))>>2)])|0);
            SHM32[(((dest)+(36))>>2)]=((HEAP32[(((src)+(36))>>2)])|0);
            SHM32[(((dest)+(40))>>2)]=((HEAP32[(((src)+(40))>>2)])|0);
            SHM32[(((dest)+(44))>>2)]=((HEAP32[(((src)+(44))>>2)])|0);
            SHM32[(((dest)+(48))>>2)]=((HEAP32[(((src)+(48))>>2)])|0);
            SHM32[(((dest)+(52))>>2)]=((HEAP32[(((src)+(52))>>2)])|0);
            SHM32[(((dest)+(56))>>2)]=((HEAP32[(((src)+(56))>>2)])|0);
            SHM32[(((dest)+(60))>>2)]=((HEAP32[(((src)+(60))>>2)])|0);
            dest = (dest+64)|0;
            src = (src+64)|0;
          }
          while ((dest|0) < (aligned_dest_end|0) ) {
            SHM32[((dest)>>2)]=((HEAP32[((src)>>2)])|0);
            dest = (dest+4)|0;
            src = (src+4)|0;
          }
        } else {
          // In the unaligned copy case, unroll a bit as well.
          aligned_dest_end = (dest_end - 4)|0;
          while ((dest|0) < (aligned_dest_end|0) ) {
            SHM8[((dest)>>0)]=((HEAP8[((src)>>0)])|0);
            SHM8[(((dest)+(1))>>0)]=((HEAP8[(((src)+(1))>>0)])|0);
            SHM8[(((dest)+(2))>>0)]=((HEAP8[(((src)+(2))>>0)])|0);
            SHM8[(((dest)+(3))>>0)]=((HEAP8[(((src)+(3))>>0)])|0);
            dest = (dest+4)|0;
            src = (src+4)|0;
          }
        }
        // The remaining unaligned < 4 byte tail.
        while ((dest|0) < (dest_end|0)) {
          SHM8[((dest)>>0)]=((HEAP8[((src)>>0)])|0);
          dest = (dest+1)|0;
          src = (src+1)|0;
        }
        return ret|0;
      };

      exports.copyToUser = function(dest, src, num) {
        dest = dest|0; src = src|0; num = num|0;
        var SHM8 = BROWSIX.browsix.shm8;
        var SHM32 = BROWSIX.browsix.shm32;
        var ret = 0;
        var aligned_dest_end = 0;
        var block_aligned_dest_end = 0;
        var dest_end = 0;
        // Test against a benchmarked cutoff limit for when HEAPU8.set() becomes faster to use.
        if ((num|0) >=
          8192
        ) {
          return BROWSIX.browsix.copyToUserBig(dest|0, src|0, num|0)|0;
        }

        ret = dest|0;
        dest_end = (dest + num)|0;
        if ((dest&3) == (src&3)) {
          // The initial unaligned < 4-byte front.
          while (dest & 3) {
            if ((num|0) == 0) return ret|0;
            HEAP8[((dest)>>0)]=((SHM8[((src)>>0)])|0);
            dest = (dest+1)|0;
            src = (src+1)|0;
            num = (num-1)|0;
          }
          aligned_dest_end = (dest_end & -4)|0;
          block_aligned_dest_end = (aligned_dest_end - 64)|0;
          while ((dest|0) <= (block_aligned_dest_end|0) ) {
            HEAP32[((dest)>>2)]=((SHM32[((src)>>2)])|0);
            HEAP32[(((dest)+(4))>>2)]=((SHM32[(((src)+(4))>>2)])|0);
            HEAP32[(((dest)+(8))>>2)]=((SHM32[(((src)+(8))>>2)])|0);
            HEAP32[(((dest)+(12))>>2)]=((SHM32[(((src)+(12))>>2)])|0);
            HEAP32[(((dest)+(16))>>2)]=((SHM32[(((src)+(16))>>2)])|0);
            HEAP32[(((dest)+(20))>>2)]=((SHM32[(((src)+(20))>>2)])|0);
            HEAP32[(((dest)+(24))>>2)]=((SHM32[(((src)+(24))>>2)])|0);
            HEAP32[(((dest)+(28))>>2)]=((SHM32[(((src)+(28))>>2)])|0);
            HEAP32[(((dest)+(32))>>2)]=((SHM32[(((src)+(32))>>2)])|0);
            HEAP32[(((dest)+(36))>>2)]=((SHM32[(((src)+(36))>>2)])|0);
            HEAP32[(((dest)+(40))>>2)]=((SHM32[(((src)+(40))>>2)])|0);
            HEAP32[(((dest)+(44))>>2)]=((SHM32[(((src)+(44))>>2)])|0);
            HEAP32[(((dest)+(48))>>2)]=((SHM32[(((src)+(48))>>2)])|0);
            HEAP32[(((dest)+(52))>>2)]=((SHM32[(((src)+(52))>>2)])|0);
            HEAP32[(((dest)+(56))>>2)]=((SHM32[(((src)+(56))>>2)])|0);
            HEAP32[(((dest)+(60))>>2)]=((SHM32[(((src)+(60))>>2)])|0);
            dest = (dest+64)|0;
            src = (src+64)|0;
          }
          while ((dest|0) < (aligned_dest_end|0) ) {
            HEAP32[((dest)>>2)]=((SHM32[((src)>>2)])|0);
            dest = (dest+4)|0;
            src = (src+4)|0;
          }
        } else {
          // In the unaligned copy case, unroll a bit as well.
          aligned_dest_end = (dest_end - 4)|0;
          while ((dest|0) < (aligned_dest_end|0) ) {
            HEAP8[((dest)>>0)]=((SHM8[((src)>>0)])|0);
            HEAP8[(((dest)+(1))>>0)]=((SHM8[(((src)+(1))>>0)])|0);
            HEAP8[(((dest)+(2))>>0)]=((SHM8[(((src)+(2))>>0)])|0);
            HEAP8[(((dest)+(3))>>0)]=((SHM8[(((src)+(3))>>0)])|0);
            dest = (dest+4)|0;
            src = (src+4)|0;
          }
        }
        // The remaining unaligned < 4 byte tail.
        while ((dest|0) < (dest_end|0)) {
          HEAP8[((dest)>>0)]=((SHM8[((src)>>0)])|0);
          dest = (dest+1)|0;
          src = (src+1)|0;
        }
        return ret|0;
      };

      exports.copyFromUserBig = function(dest, src, num) {
        BROWSIX.browsix.shmU8.set(HEAPU8.subarray(src, src+num), dest);
      };

      exports.copyToUserBig = function(dest, src, num) {
        HEAPU8.set(BROWSIX.browsix.shmU8.subarray(src, src+num), dest);
      };

      var SyscallResponse = (function () {
        function SyscallResponse(id, name, args) {
          this.id = id;
          this.name = name;
          this.args = args;
        };
        return SyscallResponse;
      })();
      exports.SyscallResponseFrom = function (ev) {
        var requiredOnData = ['id', 'name', 'args'];
        if (!ev.data)
          return;
        for (var i = 0; i < requiredOnData.length; i++) {
          if (!ev.data.hasOwnProperty(requiredOnData[i]))
            return;
        }
        var args = ev.data.args; //.map(convertApiErrors);
        return {id: ev.data.id, name: ev.data.name, args: args};
      };

      var USyscalls = (function () {
        function USyscalls(port) {
          this.msgIdSeq = 1;
          this.outstanding = {};
          this.signalHandlers = {};
        }
        USyscalls.prototype.syscallAsync = function (cb, name, args, transferrables) {
          var msgId = this.nextMsgId();
          this.outstanding[msgId] = cb;
          self.postMessage({
            id: msgId,
            name: name,
            args: args,
          }, transferrables);
        };
        USyscalls.prototype.sync = function (trap, a1, a2, a3, a4, a5, a6) {
          const waitOff = BROWSIX.browsix.waitOff;
          const waitOff32 = waitOff >> 2;
          BROWSIX.browsix.shm32[waitOff + 1] = trap|0;
          BROWSIX.browsix.shm32[waitOff + 2] = a1|0;
          BROWSIX.browsix.shm32[waitOff + 3] = a2|0;
          BROWSIX.browsix.shm32[waitOff + 4] = a3|0;
          BROWSIX.browsix.shm32[waitOff + 5] = a4|0;
          BROWSIX.browsix.shm32[waitOff + 6] = a5|0;
          BROWSIX.browsix.shm32[waitOff + 7] = a6|0;
          BROWSIX.browsix.shm32[waitOff + 8] = 0;

          Atomics.store(BROWSIX.browsix.shm32, waitOff32, 0);
          self.postMessage(BROWSIX.browsix.syncMsg);
          /* var paranoid = Atomics.load(BROWSIX.browsix.shm32, waitOff >> 2)|0;
           * if (paranoid !== 1 && paranoid !== 0) {
           *   Module.printErr('WARN: someone wrote over our futex alloc(' + waitOff + '): ' + paranoid);
           *   debugger;
           * } */
          Atomics.wait(BROWSIX.browsix.shm32, waitOff32, 0);
          BROWSIX.browsix.shm32[waitOff32] = 0;
          return BROWSIX.browsix.shm32[waitOff32 + 8];
        };
        USyscalls.prototype.usleep = function(useconds) {
          // int usleep(useconds_t useconds);
          // http://pubs.opengroup.org/onlinepubs/000095399/functions/usleep.html
          var msec = useconds / 1000;
          var target = performance.now() + msec;
          var waitOff = BROWSIX.browsix.waitOff;

          var paranoid = Atomics.load(BROWSIX.browsix.shm32, (waitOff >> 2)+8);
          if (paranoid !== 0) {
            Module.printErr('WARN: someone wrote over our futex alloc(' + waitOff + '): ' + paranoid);
          }

          Atomics.store(BROWSIX.browsix.shm32, (waitOff >> 2)+8, 0);

          var msecsToSleep;
          while (performance.now() < target) {
            msecsToSleep = target - performance.now();
            if (msecsToSleep > 0) {
              Atomics.wait(BROWSIX.browsix.shm32, (waitOff >> 2)+8, 0, msecsToSleep);
            }
          }
          return 0;
        };
        USyscalls.prototype.exit = function(code) {
          if (Runtime.process && Runtime.process.env && Runtime.process.env['BROWSIX_PERF']) {
            var binary = Runtime.process.env['BROWSIX_PERF'];
            console.log('PERF: stop ' + binary);
            var stopXhr = new XMLHttpRequest();
            stopXhr.open('GET', 'http://localhost:9000/stop?binary=' + binary, false);
            stopXhr.send();
          }
          // FIXME: this will only work in sync mode.
          Module['_fflush'](0);
          if (BROWSIX.browsix.async) {
            this.syscallAsync(null, 'exit', [code]);
          } else {
            this.sync(252 /* SYS_exit_group */, code);
          }
          close();
        };
        USyscalls.prototype.addEventListener = function (type, handler) {
          if (!handler)
            return;
          if (this.signalHandlers[type])
            this.signalHandlers[type].push(handler);
          else
            this.signalHandlers[type] = [handler];
        };
        USyscalls.prototype.resultHandler = function (ev) {
          var response = BROWSIX.browsix.SyscallResponseFrom(ev);
          if (!response) {
            console.log('bad usyscall message, dropping');
            console.log(ev);
            return;
          }
          if (response.name) {
            var handlers = this.signalHandlers[response.name];
            if (handlers) {
              for (var i = 0; i < handlers.length; i++)
                handlers[i](response);
            }
            else {
              console.log('unhandled signal ' + response.name);
            }
            return;
          }
          this.complete(response.id, response.args);
        };
        USyscalls.prototype.complete = function (id, args) {
          var cb = this.outstanding[id];
          delete this.outstanding[id];
          if (cb) {
            cb.apply(undefined, args);
          }
          else {
            console.log('unknown callback for msg ' + id + ' - ' + args);
          }
        };
        USyscalls.prototype.nextMsgId = function () {
          return ++this.msgIdSeq;
        };
        return USyscalls;
      })();

      var syscall = new USyscalls();
      exports.syscall = syscall;

      function init1(data) {
        // 0: args
        // 1: environ
        // 2: debug flag
        // 3: pid (if fork)
        // 4: heap (if fork)
        // 5: fork args (if fork)

        var args = data.args[0];
        var environ = data.args[1];
        // args[4] is a copy of the heap - replace anything we just
        // alloc'd with it.
        if (data.args[4]) {
          var pid = data.args[3];
          var heap = data.args[4];
          var forkArgs = data.args[5];

          Runtime.process.parentBuffer = heap;
          Runtime.process.pid = pid;
          Runtime.process.forkArgs = forkArgs;

          updateGlobalBuffer(Runtime.process.parentBuffer);
          updateGlobalBufferViews();

          assert(HEAP32.buffer === Runtime.process.parentBuffer);

          if (typeof asmModule !== 'undefined') {
            asm = asmModule(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
          } else {
            asm = asm(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
          }
          initReceiving();

          asm.stackRestore(forkArgs.stackSave);
          asm.emtStackRestore(forkArgs.emtStackTop);
        }

        args = [args[0]].concat(args);

        Runtime.process.argv = args;
        Runtime.process.env = environ;

#if EMTERPRETIFY_ASYNC
        BROWSIX.browsix.async = true;
        if (!asm || typeof asm['_main'] === 'undefined') {
          if (typeof asmModule !== 'undefined') {
            asm = asmModule(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
          }
        }
        initReceiving();
        Runtime.process.isReady = true;
        setTimeout(function () { Runtime.process.emit('ready'); }, 0);
#else
        if (typeof SharedArrayBuffer !== 'function') {
          var done = function() {
            BROWSIX.browsix.syscall.exit(-1);
          };
          var msg = 'ERROR: requires SharedArrayBuffer support, exiting\n';
          var buf = new Uint8Array(msg.length);
          for (var i = 0; i < msg.length; i++)
            buf[i] = msg.charCodeAt(i);

          BROWSIX.browsix.syscall.syscallAsync(done, 'pwrite', [2, buf, -1]);
          console.log('Embrowsix: shared array buffers required');
          return;
        }

        if (typeof gc === 'function') gc();

        init2(0);
        function init2(attempt) {
          if (typeof gc === 'function') gc();

          var oldHEAP8 = HEAP8;
          try {
            BROWSIX.browsix.shm = new SharedArrayBuffer(BROWSIX.browsix.SHM_SIZE);
            BROWSIX.browsix.shmU8 = new Uint8Array(BROWSIX.browsix.shm);
            BROWSIX.browsix.shm8 = new Int8Array(BROWSIX.browsix.shm);
            BROWSIX.browsix.shm32 = new Int32Array(BROWSIX.browsix.shm);
          } catch (e) {
            if (attempt >= 16)
              throw e;

            console.log('couldnt allocate SharedArrayBuffer(' + REAL_TOTAL_MEMORY + '), retrying');

            var delay = 200*attempt;
            if (delay > 2000)
              delay = 2000;

            if (typeof gc === 'function') gc();
            setTimeout(init2, delay, attempt+1);
            if (typeof gc === 'function') gc();

            return;
          }

          var PER_BLOCKING = 0x80; // personality constant to tell the kernel we want blocking syscall responses

          // it seems malloc overflows into our static allocation, so
          // just reserve that, throw it away, and never use it.  The
          // first number is in bytes, no matter what the 'i*' specifier
          // is :\
          var waitOff = 0;
          BROWSIX.browsix.waitOff = waitOff;

          function personalityChanged(err) {
            if (err) {
              console.log('personality: ' + err);
              return;
            }
            BROWSIX.browsix.async = false;
            if (Runtime.process && Runtime.process.env && Runtime.process.env['BROWSIX_PERF']) {
              var binary = Runtime.process.env['BROWSIX_PERF'];
              console.log('PERF: start ' + binary);
              var stopXhr = new XMLHttpRequest();
              stopXhr.open('GET', 'http://localhost:9000/start?binary=' + binary, false);
              stopXhr.send();
            }
            Runtime.process.isReady = true;
            if (typeof asm !== 'object')
              asm = asmModule(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
            initReceiving();
            Runtime.process.emit('ready');
          }
          // the original spec called for buffer to be in the transfer
          // list, but the current spec (and dev versions of Chrome)
          // don't support that.  Try it the old way, and if it
          // doesn't work try it the new way.
          BROWSIX.browsix.syscall.syscallAsync(
            personalityChanged, 'personality',
            [PER_BLOCKING, BROWSIX.browsix.shm, waitOff], []);
        }
#endif
      }

      syscall.addEventListener('init', init1);

      exports.__syscall1 = function(which, varargs) { // exit
        SYSCALLS.varargs = varargs;
        var status = SYSCALLS.get();
        Module['exit'](status);
        return 0;
      };
      exports.__syscall2 = function(which, varargs) { // fork
        SYSCALLS.varargs = varargs;
        abort('TODO: fork not currently supported in sync Browsix');
      };
      exports.__syscall3 = function(which, varargs) { // read
        SYSCALLS.varargs = varargs;
        let SYS_READ = 3;
        let fd = SYSCALLS.get(), ptr = SYSCALLS.get(), len = SYSCALLS.get();
        let ret = 0;

        while (len > 0) {
          let shmLen = BROWSIX.browsix.getShmLen(len);
          let shmOff = BROWSIX.browsix.SHM_OFF

          let count = BROWSIX.browsix.syscall.sync(SYS_READ, fd, shmOff, shmLen);
          if (count < 0) {
            return ret === 0 ? count : ret;
          }

          BROWSIX.browsix.copyToUser(ptr, shmOff, count);
          ret += count;

          ptr += shmLen;
          len -= shmLen;
        }
        return ret;
      };
      exports.__syscall4 = function(which, varargs) { // write
        SYSCALLS.varargs = varargs;
        let SYS_WRITE = 4;
        let fd = SYSCALLS.get(), ptr = SYSCALLS.get(), len = SYSCALLS.get();
        let ret = 0;

        // it is possible for the buffer being written to be larger
        // than our shared memory segment.  In the common case this
        // while loop executes once, but for large source buffers
        // will iterate several times.
        while (len > 0) {
          let shmLen = BROWSIX.browsix.getShmLen(len);
          let shmOff = BROWSIX.browsix.SHM_OFF;

          BROWSIX.browsix.copyFromUser(shmOff, ptr, shmLen);

          let written = BROWSIX.browsix.syscall.sync(SYS_WRITE, fd, shmOff, len);
          if (written < 0) {
            return ret === 0 ? written : ret;
          }
          ret += written;

          ptr += shmLen;
          len -= shmLen;
        }

        return ret;
      };
      exports.__syscall5 = function(which, varargs) { // open
        SYSCALLS.varargs = varargs;
        let SYS_OPEN = 5;
        let path = SYSCALLS.get(), flags = SYSCALLS.get(), mode = SYSCALLS.get();
        BROWSIX.browsix.putShmString(BROWSIX.browsix.SHM_OFF, path);
        return BROWSIX.browsix.syscall.sync(SYS_OPEN, BROWSIX.browsix.SHM_OFF, flags, mode);
      };
      exports.__syscall6 = function(which, varargs) { // close
        SYSCALLS.varargs = varargs;
        let SYS_CLOSE = 6;
        let fd = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_CLOSE, fd);
      };
      exports.__syscall9 = function(which, varargs) { // link
        SYSCALLS.varargs = varargs;
        console.log('TODO: link');
        let oldpath = SYSCALLS.get(), newpath = SYSCALLS.get();
        return -ERRNO_CODES.EMLINK; // no hardlinks for us
      };
      exports.__syscall10 = function(which, varargs) { // unlink
        SYSCALLS.varargs = varargs;
        let SYS_UNLINK = 10;
        let path = SYSCALLS.get();
        BROWSIX.browsix.putShmString(BROWSIX.browsix.SHM_OFF, path);
        return BROWSIX.browsix.syscall.sync(SYS_UNLINK, BROWSIX.browsix.SHM_OFF);
      };
      exports.__syscall11 = function(which, varargs) { // execve
        SYSCALLS.varargs = varargs;
        let SYS_EXECVE = 11;
        let filename = SYSCALLS.get(), argv = SYSCALLS.get(), envp = SYSCALLS.get();
        console.log('TODO: execve');
        // need to think about copying argv + envp into shm
        return BROWSIX.browsix.syscall.sync(SYS_EXECVE, filename, argv, envp);
      };
      exports.__syscall12 = function(which, varargs) { // chdir
        SYSCALLS.varargs = varargs;
        let SYS_CHDIR = 12;
        let path = SYSCALLS.get();
        BROWSIX.browsix.putShmString(BROWSIX.browsix.SHM_OFF, path);
        return BROWSIX.browsix.syscall.sync(SYS_CHDIR, BROWSIX.browsix.SHM_OFF);
      };
      exports.__syscall20 = function(which, varargs) { // getpid
        SYSCALLS.varargs = varargs;
        let SYS_GETPID = 20;
        return BROWSIX.browsix.syscall.sync(SYS_GETPID);
      };
      exports.__syscall33 = function(which, varargs) { // access
        SYSCALLS.varargs = varargs;
        var SYS_ACCESS = 33;
        var path = SYSCALLS.get(), amode = SYSCALLS.get();
        BROWSIX.browsix.putShmString(BROWSIX.browsix.SHM_OFF, path);
        return BROWSIX.browsix.syscall.sync(SYS_ACCESS, BROWSIX.browsix.SHM_OFF, amode);
      };
      exports.__syscall37 = function(which, varargs) { // kill
        SYSCALLS.varargs = varargs;
        let SYS_KILL = 37;
        let pid = SYSCALLS.get(), sig = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_KILL, pid, sig);
      };
      exports.__syscall38 = function(which, varargs) { // rename
        SYSCALLS.varargs = varargs;
        let SYS_RENAME = 38;
        let old_path = SYSCALLS.get(), new_path = SYSCALLS.get();
        let old_path_off = BROWSIX.browsix.SHM_OFF;
        let new_path_off = BROWSIX.browsix.putShmString(old_path_off, old_path);
        BROWSIX.browsix.putShmString(new_path_off, new_path);
        return BROWSIX.browsix.syscall.sync(SYS_RENAME, old_path_off, new_path_off);
      };
      exports.__syscall39 = function(which, varargs) { // mkdir
        SYSCALLS.varargs = varargs;
        let SYS_MKDIR = 39;
        let path = SYSCALLS.get(), mode = SYSCALLS.get();
        let path_off = BROWSIX.browsix.SHM_OFF;
        BROWSIX.browsix.putShmString(path_off, path);
        return BROWSIX.browsix.syscall.sync(SYS_MKDIR, path_off, mode);
      };
      exports.__syscall40 = function(which, varargs) { // rmdir
        SYSCALLS.varargs = varargs;
        let SYS_RMDIR = 40;
        let path = SYSCALLS.get();
        let path_off = BROWSIX.browsix.SHM_OFF;
        BROWSIX.browsix.putShmString(path_off, path);
        return BROWSIX.browsix.syscall.sync(SYS_RMDIR, path_off);
      };
      exports.__syscall41 = function(which, varargs) { // dup
        SYSCALLS.varargs = varargs;
        let SYS_DUP = 41;
        let fd1 = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_DUP, fd1);
      }
      exports.__syscall42 = function(which, varargs) { // pipe
        SYSCALLS.varargs = varargs;
        let SYS_PIPE2 = 41;
        let pipefd = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_PIPE2, pipefd, 0);
      };
      exports.__syscall54 = function(which, varargs) { // ioctl
        SYSCALLS.varargs = varargs;
        let SYS_IOCTL = 54;
        let fd = SYSCALLS.get(), op = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_IOCTL, fd, op);
      };
      exports.__syscall63 = function(which, varargs) { // dup2
        SYSCALLS.varargs = varargs;
        let SYS_DUP3 = 330;
        let fd1 = SYSCALLS.get(), fd2 = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_DUP3, fd1, fd2, 0);
      };
      exports.__syscall64 = function(which, varargs) { // getppid
        SYSCALLS.varargs = varargs;
        let SYS_GETPPID = 64;
        return BROWSIX.browsix.syscall.sync(SYS_GETPPID);
      };
      exports.__syscall83 = function(which, varargs) { // symlink
        SYSCALLS.varargs = varargs;
        console.log('TODO: symlink');
        abort('unsupported syscall symlink');
        return 0;
      };
      exports.__syscall85 = function(which, varargs) { // readlink
        SYSCALLS.varargs = varargs;
        console.log('TODO: readlink');
        abort('unsupported syscall readlink');
        return 0;
      };
      exports.__syscall91 = function(which, varargs) { // munmap
        SYSCALLS.varargs = varargs;
        console.log('TODO: munmap');
        abort('unsupported syscall munmap');
      };
      exports.__syscall94 = function(which, varargs) { // fchmod
        SYSCALLS.varargs = varargs;
        console.log('TODO: fchmod');
        //abort('unsupported syscall fchmod');
        return 0;
      };
      exports.__syscall96 = function(which, varargs) { // getpriority
        SYSCALLS.varargs = varargs;
        return 0;
      };
      exports.__syscall97 = function(which, varargs) { // setpriority
        SYSCALLS.varargs = varargs;
        return -ERRNO_CODES.EPERM;
      };
      exports.__syscall102 = function(which, varargs) { // socketcall
        SYSCALLS.varargs = varargs;
        console.log('TODO: socketcall');
        abort('unsupported syscall socketcall');
        return -ERRNO_CODES.EPERM;
      }
      exports.__syscall140 = function(which, varargs) { // llseek
        SYSCALLS.varargs = varargs;
        let SYS_LLSEEK = 140;
        let fd = SYSCALLS.get(), offhi = SYSCALLS.get(), offlo = SYSCALLS.get(), result = SYSCALLS.get(), whence = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_LLSEEK, fd, offhi, offlo, result, whence);
      };
      exports.__syscall142 = function(which, varargs) { // newselect
        SYSCALLS.varargs = varargs;
        console.log('TODO: socketcall');
        abort('newselect not implemented');
        return;
      };
      exports.__syscall145 = function(which, varargs) { // readv
        SYSCALLS.varargs = varargs;
        let SYS_READ = 3;
        let fd = SYSCALLS.get(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();
        let ret = 0;
        for (var i = 0; i < iovcnt; i++) {
          var ptr = {{{ makeGetValue('iov', 'i*8', 'i32') }}};
          var len = {{{ makeGetValue('iov', 'i*8 + 4', 'i32') }}};
          if (len === 0)
            continue;
          // it is possible for the buffer being written to be larger
          // than our shared memory segment.  In the common case this
          // while loop executes once, but for large source buffers
          // will iterate several times.
          while (len > 0) {
            let shmLen = BROWSIX.browsix.getShmLen(len);
            let shmOff = BROWSIX.browsix.SHM_OFF;

            let count = BROWSIX.browsix.syscall.sync(SYS_READ, fd, shmOff, shmLen);
            if (count < 0)
              return ret === 0 ? count : ret;

            BROWSIX.browsix.copyToUser(ptr, shmOff, count);
            ret += count;

            ptr += shmLen;
            len -= shmLen;
          }
        }
        return ret;
      };
      exports.__syscall146 = function(which, varargs) { // writev
        SYSCALLS.varargs = varargs;
        let SYS_WRITE = 4;
        let fd = SYSCALLS.get(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();
        let ret = 0;
        for (let i = 0; i < iovcnt; i++) {
          let ptr = {{{ makeGetValue('iov', 'i*8', 'i32') }}};
          let len = {{{ makeGetValue('iov', 'i*8 + 4', 'i32') }}};
          if (len === 0)
            continue;
          // it is possible for the buffer being written to be larger
          // than our shared memory segment.  In the common case this
          // while loop executes once, but for large source buffers
          // will iterate several times.
          while (len > 0) {
            let shmLen = BROWSIX.browsix.getShmLen(len);
            let shmOff = BROWSIX.browsix.SHM_OFF;

            BROWSIX.browsix.copyFromUser(shmOff, ptr, shmLen);

            let written = BROWSIX.browsix.syscall.sync(SYS_WRITE, fd, shmOff, shmLen);
            if (written < 0) {
              return ret === 0 ? written : ret;
            }
            ret += written;

            ptr += shmLen;
            len -= shmLen;
          }
        }
        return ret;
      };
      exports.__syscall168 = function(which, varargs) { // poll
        SYSCALLS.varargs = varargs;
        console.log('TODO: poll');
        abort('poll not implemented');
        return;
      };
      exports.__syscall174 = function(which, varargs) { // rt_sigaction
        SYSCALLS.varargs = varargs;
        let SYS_SIGACTION = 174;
        let signum = SYSCALLS.get(), act = SYSCALLS.get(), oldact = SYSCALLS.get();

        // if act->sa_handler == SIG_DFL or SIG_IGN, pass along to
        // kernel.  otherwise, register the pointer here somewhere.
        // and figure out how to invoke it?

        return BROWSIX.browsix.syscall.sync(SYS_SIGACTION, signum, act, oldact);
      };
      exports.__syscall175 = function(which, varargs) { // rt_sigprocmask
        SYSCALLS.varargs = varargs;
        let SYS_SIGPROCMASK = 174;
        let how = SYSCALLS.get(), set = SYSCALLS.get(), oldset = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_SIGPROCMASK, how, set, oldset);
      };
      exports.__syscall183 = function(which, varargs) { // getcwd
        SYSCALLS.varargs = varargs;
        let SYS_GETCWD = 183;
        let ptr = SYSCALLS.get(), len = SYSCALLS.get();
        let shmLen = BROWSIX.browsix.getShmLen(len);
        let shmOff = BROWSIX.browsix.SHM_OFF;
        let count = BROWSIX.browsix.syscall.sync(SYS_GETCWD, shmOff, shmLen);
        if (count < 0) {
          return count;
        }
        BROWSIX.browsix.copyToUser(ptr, shmOff, count);
        return count;
      };
      exports.__syscall195 = function(which, varargs) { // SYS_stat64
        SYSCALLS.varargs = varargs;
        let SYS_STAT = 195;
        let path = SYSCALLS.get(), ptr = SYSCALLS.get();
        let pathOff = BROWSIX.browsix.SHM_OFF;
        let bufOff = BROWSIX.browsix.putShmString(pathOff, path);
        let shmLen = BROWSIX.browsix.getShmLenAt(bufOff, {{{ C_STRUCTS.stat.__size__ }}});
        let ret = BROWSIX.browsix.syscall.sync(SYS_STAT, pathOff, bufOff);
        if (ret === 0) {
          BROWSIX.browsix.copyToUser(ptr, bufOff, shmLen);
        }
        return ret;
      };
      exports.__syscall196 = function(which, varargs) { // SYS_lstat64
        SYSCALLS.varargs = varargs;
        let SYS_LSTAT = 196;
        let path = SYSCALLS.get(), ptr = SYSCALLS.get();
        let pathOff = BROWSIX.browsix.SHM_OFF;
        let bufOff = BROWSIX.browsix.putShmString(pathOff, path);
        let shmLen = BROWSIX.browsix.getShmLenAt(bufOff, {{{ C_STRUCTS.stat.__size__ }}});
        let ret = BROWSIX.browsix.syscall.sync(SYS_LSTAT, pathOff, bufOff);
        if (ret === 0) {
          BROWSIX.browsix.copyToUser(ptr, bufOff, shmLen);
        }
        return ret;
      };
      exports.__syscall197 = function(which, varargs) { // SYS_fstat64
        SYSCALLS.varargs = varargs;
        let SYS_FSTAT = 197;
        let path = SYSCALLS.get(), ptr = SYSCALLS.get();
        let pathOff = BROWSIX.browsix.SHM_OFF;
        let bufOff = BROWSIX.browsix.putShmString(pathOff, path);
        let shmLen = BROWSIX.browsix.getShmLenAt(bufOff, {{{ C_STRUCTS.stat.__size__ }}});
        let ret = BROWSIX.browsix.syscall.sync(SYS_FSTAT, pathOff, bufOff);
        if (ret === 0) {
          BROWSIX.browsix.copyToUser(ptr, bufOff, shmLen);
        }
        return ret;
      };
      exports.__syscall220 = function(which, varargs) { // SYS_getdents64
        SYSCALLS.varargs = varargs;
        let SYS_GETDENTS64 = 220;
        let fd = SYSCALLS.get(), dirp = SYSCALLS.get(), count = SYSCALLS.get();
        // let shmBuf = BROWSIX.browsix.getShm({{{ C_STRUCTS.dirent.__size__ }}} * count);
        let shmLen = BROWSIX.browsix.getShmLen(count);
        let shmOff = BROWSIX.browsix.SHM_OFF;
        let ret = BROWSIX.browsix.syscall.sync(SYS_GETDENTS64, fd, shmOff, shmLen);
        if (ret >= 0) {
          BROWSIX.browsix.copyToUser(dirp, shmOff, shmLen);
        }
        return ret;
      };
      exports.__syscall221 = function(which, varargs) { // fcntl64
        SYSCALLS.varargs = varargs;
        let SYS_FCNTL64 = 221;
        let fd = SYSCALLS.get(), cmd = SYSCALLS.get();
        let arg = 0;

        // only some of the commands have multiple arguments.
        switch (cmd) {
          case {{{ cDefine('F_DUPFD') }}}:
          case {{{ cDefine('F_SETFD') }}}:
          case {{{ cDefine('F_SETFL') }}}:
          case {{{ cDefine('F_GETLK') }}}:
          case {{{ cDefine('F_GETLK64') }}}:
            arg = SYSCALLS.get();
        }

        return BROWSIX.browsix.syscall.sync(SYS_FCNTL64, fd, cmd, arg);
      };
      exports.__syscall330 = function(which, varargs) { // dup3
        SYSCALLS.varargs = varargs;
        let SYS_DUP3 = 330;
        let fd1 = SYSCALLS.get(), fd2 = SYSCALLS.get(), flags = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_DUP3, fd1, fd2, flags);
      };
      exports.__syscall331 = function(which, varargs) { // pipe2
        SYSCALLS.varargs = varargs;
        let SYS_PIPE2 = 41;
        let pipefd = SYSCALLS.get(), flags = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_PIPE2, pipefd, flags);
      };

      return exports;
    }()),
  },
};

// for (var x in BrowsixLibrary) {
//   var m = /^__browsix_syscall(\d+)$/.exec(x);
//   if (!m) continue;
//   var which = +m[1];
//   var t = BrowsixLibrary[x];
//   if (typeof t === 'string') continue;
//   t = t.toString();
//   var pre = '', post = '';
// #if USE_PTHREADS
//   pre += 'if (ENVIRONMENT_IS_PTHREAD) { return _emscripten_sync_run_in_main_thread_2({{{ cDefine("EM_PROXIED_SYSCALL") }}}, ' + which + ', varargs) }\n';
// #endif
//   pre += 'SYSCALLS.varargs = varargs;\n';
// #if SYSCALL_DEBUG
//   pre += "Module.printErr('syscall! ' + [" + which + ", '" + SYSCALL_CODE_TO_NAME[which] + "']);\n";
//   pre += "var canWarn = true;\n";
//   pre += "var ret = (function() {\n";
//   post += "})();\n";
//   post += "if (ret < 0 && canWarn) {\n";
//   post += "  Module.printErr('error: syscall may have failed with ' + (-ret) + ' (' + ERRNO_MESSAGES[-ret] + ')');\n";
//   post += "}\n";
//   post += "Module.printErr('syscall return: ' + ret);\n";
//   post += "return ret;\n";
// #endif
//   pre += 'try {\n';
//   var handler =
//   "} catch (e) {\n" +
//   "  if (typeof FS === 'undefined' || !(e instanceof FS.ErrnoError)) abort(e);\n";
// #if SYSCALL_DEBUG
//   handler +=
//   "  Module.printErr('error: syscall failed with ' + e.errno + ' (' + ERRNO_MESSAGES[e.errno] + ')');\n" +
//   "  canWarn = false;\n";
// #endif
//   handler +=
//   "  return -e.errno;\n" +
//   "}\n";
//   post = handler + post;
//
//   if (pre) {
//     var bodyStart = t.indexOf('{') + 1;
//     t = t.substring(0, bodyStart) + pre + t.substring(bodyStart);
//   }
//   if (post) {
//     var bodyEnd = t.lastIndexOf('}');
//     t = t.substring(0, bodyEnd) + post + t.substring(bodyEnd);
//   }
//   BrowsixLibrary[x] = eval('(' + t + ')');
//   if (!BrowsixLibrary[x + '__deps']) BrowsixLibrary[x + '__deps'] = [];
//   // BrowsixLibrary[x + '__deps'].push('$BROWSIX');
//   // BrowsixLibrary['$BROWSIX__deps'].push(x)
// }


mergeInto(LibraryManager.library, BrowsixLibrary);
