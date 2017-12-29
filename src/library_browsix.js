var BrowsixLibrary = {
  $BROWSIX__deps: [
#if EMTERPRETIFY_ASYNC
                   '$EmterpreterAsync', 'fflush',
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
      exports.syncMsg = {
        trap: 0|0,
        args: [0|0, 0|0, 0|0, 0|0, 0|0, 0|0],
      };

      exports.SHM_SIZE = {{{ BROWSIX_SHM_SIZE }}};
      exports.shm = null;
      exports.shmU8 = null;
      exports.shm32 = null;
      exports.SHM_OFF = 128;
      exports.SHM_BUF_SIZE = {{{ BROWSIX_SHM_SIZE - 128 }}};

      exports.getShm = function(len) {
        if (len > BROWSIX.browsix.SHM_BUF_SIZE)
          len = BROWSIX.browsix.SHM_BUF_SIZE;

        let off = BROWSIX.browsix.SHM_OFF;
        return new Uint8Array(BROWSIX.browsix.shm, off, len);
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
          var waitOff = BROWSIX.browsix.waitOff;
          var syncMsg = BROWSIX.browsix.syncMsg;
          syncMsg.trap = trap|0;
          syncMsg.args[0] = a1|0;
          syncMsg.args[1] = a2|0;
          syncMsg.args[2] = a3|0;
          syncMsg.args[3] = a4|0;
          syncMsg.args[4] = a5|0;
          syncMsg.args[5] = a6|0;

          Atomics.store(BROWSIX.browsix.shm32, waitOff >> 2, 0);
          self.postMessage(syncMsg);
          var paranoid = Atomics.load(BROWSIX.browsix.shm32, waitOff >> 2)|0;
          if (paranoid !== 1 && paranoid !== 0) {
            Module.printErr('WARN: someone wrote over our futex alloc(' + waitOff + '): ' + paranoid);
            debugger;
          }
          Atomics.wait(BROWSIX.browsix.shm32, waitOff >> 2, 0);
          Atomics.store(BROWSIX.browsix.shm32, waitOff >> 2, 0);
          return Atomics.load(BROWSIX.browsix.shm32, (waitOff >> 2) + 1);
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

          if (typeof asmModule !== 'undefined')
            asm = asmModule(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
          else
            asm = asm(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
          initReceiving();
          initRuntimeFuncs();

          asm.stackRestore(forkArgs.stackSave);
          asm.emtStackRestore(forkArgs.emtStackTop);
        }

        args = [args[0]].concat(args);

        Runtime.process.argv = args;
        Runtime.process.env = environ;

#if EMTERPRETIFY_ASYNC
        BROWSIX.browsix.async = true;
        if (!asm || typeof asm['_main'] === 'undefined') {
          if (typeof asmModule !== 'undefined')
            asm = asmModule(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
          else
            asm = asm(Module.asmGlobalArg, Module.asmLibraryArg, buffer);
        }
        initReceiving();
        initRuntimeFuncs();
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

        init2();
        function init2(attempt) {
          if (!attempt)
            attempt = 0;

          if (typeof gc === 'function') gc();

          var oldHEAP8 = HEAP8;
          try {
            BROWSIX.browsix.shm = new SharedArrayBuffer(BROWSIX.browsix.SHM_SIZE);
            BROWSIX.browsix.shmU8 = new Uint8Array(BROWSIX.browsix.shm);
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

          // the original spec called for buffer to be in the transfer
          // list, but the current spec (and dev versions of Chrome)
          // don't support that.  Try it the old way, and if it
          // doesn't work try it the new way.
          BROWSIX.browsix.syscall.syscallAsync(personalityChanged, 'personality',
                                               [PER_BLOCKING, BROWSIX.browsix.shm, waitOff], []);
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
            initRuntimeFuncs();
            Runtime.process.emit('ready');
          }
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
          let shmBuf = BROWSIX.browsix.getShm(len);

          let count = BROWSIX.browsix.syscall.sync(SYS_READ, fd, BROWSIX.browsix.SHM_OFF, shmBuf.length);

          if (count < 0)
              return ret === 0 ? count : ret;

          // TODO: this potentially overcopies if count is much
          // shorter than buffer size.  Optimize if it matters.
          (new Uint8Array(buffer, ptr, shmBuf.length)).set(shmBuf);
          ret += count;

          ptr += shmBuf.length;
          len -= shmBuf.length;
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
          let shmBuf = BROWSIX.browsix.getShm(len);
          shmBuf.set(new Uint8Array(buffer, ptr, shmBuf.length));

          var written = BROWSIX.browsix.syscall.sync(SYS_WRITE, fd, BROWSIX.browsix.SHM_OFF, shmBuf.length);
          if (written < 0)
            return ret === 0 ? written : ret;
          ret += written;

          ptr += shmBuf.length;
          len -= shmBuf.length;
        }

        return ret;
      };
      exports.__syscall6 = function(which, varargs) { // close
        SYSCALLS.varargs = varargs;
        var SYS_CLOSE = 6;
        var fd = SYSCALLS.get();
        return BROWSIX.browsix.syscall.sync(SYS_CLOSE, fd);
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
            let shmBuf = BROWSIX.browsix.getShm(len);
            shmBuf.set(new Uint8Array(buffer, ptr, shmBuf.length));

            var written = BROWSIX.browsix.syscall.sync(SYS_WRITE, fd, BROWSIX.browsix.SHM_OFF, shmBuf.length);
            if (written < 0)
              return ret === 0 ? written : ret;
            ret += written;

            ptr += shmBuf.length;
            len -= shmBuf.length;
          }
        }
        return ret;
      };

      return exports;
    }()),
  },
  /*
  __syscall5: function(which, varargs) { // open
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get(), flags = SYSCALLS.get(), mode = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(err, fd) {
          resume(function() {
              return err ? err : fd;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'open', [pathname, flags, mode]);
    });
#else
      var SYS_OPEN = 5;
      var path = SYSCALLS.get(), flags = SYSCALLS.get(), mode = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_OPEN, path, flags, mode);
#endif
    }
#endif
    var pathname = SYSCALLS.getStr(), flags = SYSCALLS.get(), mode = SYSCALLS.get() // optional TODO
    var stream = FS.open(pathname, flags, mode);
    return stream.fd;
  },
  __syscall6: function(which, varargs) { // close
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd = SYSCALLS.get();
        var done = function(err) {
          resume(function() {
            return err;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'close', [fd]);
      });
#else
      var SYS_CLOSE = 6;
      var fd = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_CLOSE, fd);
#endif
    }
#endif
    var stream = SYSCALLS.getStreamFromFD();
    FS.close(stream);
    return 0;
  },
  __syscall9: function(which, varargs) { // link
    var oldpath = SYSCALLS.get(), newpath = SYSCALLS.get();
    return -ERRNO_CODES.EMLINK; // no hardlinks for us
  },
  __syscall10: function(which, varargs) { // unlink
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(err) {
          resume(function() {
            return err;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'unlink', [pathname]);
      });
#else
      var SYS_UNLINK = 10;
      var path = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_UNLINK, path);
#endif
    }
#endif
    var path = SYSCALLS.getStr();
    FS.unlink(path);
    return 0;
  },
  __syscall11: function(which, varargs) { // execve
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      function strp(inp) {
        var ho = [{{{ heapAndOffset('HEAPU8', 'inp') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        return h.subarray(ptr, ptr+i);
      }

      // pulls a null-terimated array of strings out of memory, into an
      // array of Uint8Arrays.
      function arrp(inp) {
        var ho = [{{{ heapAndOffset('HEAPU32', 'inp') }}}];
        var h = ho[0], ptr = ho[1];

        var arr = []
        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i32', 0, 1) }}};
          if (t === 0)
            break;
          arr.push(strp(t));
          i += 4;
        }
        return arr;
      }

      return EmterpreterAsync.handle(function(resume) {
        var filename_p = SYSCALLS.get(), argv = SYSCALLS.get(), envp = SYSCALLS.get();

        var filename = strp(filename_p);
        var args = arrp(argv);
        var env = arrp(envp);

        // exec can fail if the file is not there, or not executable.
        // If successful, this syscall won't complete.
        var done = function(err) {
          resume(function() {
            return err;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'execve', [filename, args, env]);
      });
#else
      var SYS_EXECVE = 11;
      var filename = SYSCALLS.get(), argv = SYSCALLS.get(), envp = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_EXECVE, filename, argv, envp);
#endif
    }
#endif
    abort('execve not supported without Browsix');
  },
  __syscall12: function(which, varargs) { // chdir
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(err) {
          resume(function() {
            return err;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'chdir', [pathname]);
      });
#else
      var SYS_CHDIR = 12;
      var pathname = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_CHDIR, pathname);
#endif
    }
#endif
    var path = SYSCALLS.getStr();
    FS.chdir(path);
    return 0;
  },
  __syscall14: function(which, varargs) { // mknod
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: mknod');
      abort('unsupported syscall mknod');
    }
#endif
    var path = SYSCALLS.getStr(), mode = SYSCALLS.get(), dev = SYSCALLS.get();
    return SYSCALLS.doMknod(path, mode, dev);
  },
  __syscall15: function(which, varargs) { // chmod
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: chmod');
      return 0;
    }
#endif
    var path = SYSCALLS.getStr(), mode = SYSCALLS.get();
    FS.chmod(path, mode);
    return 0;
  },
  __syscall20__deps: ['$PROCINFO'],
  __syscall20: function(which, varargs) { // getpid
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var done = function(err, pid) {
          resume(function() {
            return err ? (err|0) : pid;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'getpid');
      });
#else
      var SYS_GETPID = 20;
      return BROWSIX.browsix.syscall.sync(SYS_GETPID);
#endif
    }
#endif
    return PROCINFO.pid;
  },
  __syscall29: function(which, varargs) { // pause
    console.log('TODO: pause');
    return -ERRNO_CODES.EINTR; // we can't pause
  },
  __syscall33: function(which, varargs) { // access
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get(), flags = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(result) {
          resume(function() {
            return result;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'access', [pathname, flags]);
      });
#else
      var SYS_ACCESS = 33;
      var path = SYSCALLS.get(), amode = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_ACCESS, path, amode);
#endif
    }
#endif
    var path = SYSCALLS.getStr(), amode = SYSCALLS.get();
    return SYSCALLS.doAccess(path, amode);
  },
  __syscall34: function(which, varargs) { // nice
    console.log('TODO: nice');
    var inc = SYSCALLS.get();
    return -ERRNO_CODES.EPERM; // no meaning to nice for our single-process environment
  },
  __syscall36: function(which, varargs) { // sync
    console.log('TODO: sync');
    return 0;
  },
  __syscall37: function(which, varargs) { // kill
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pid = SYSCALLS.get(), sig = SYSCALLS.get();

        var done = function(result) {
          resume(function() {
            return result;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'kill', [pid, sig]);
      });
#else
      var SYS_KILL = 37;
      var pid = SYSCALLS.get(), sig = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_KILL, pid, sig);
#endif
    }
#endif
    abort('kill not implemented outside Browsix');
    return 0;
  },
  __syscall38: function(which, varargs) { // rename
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var old_path_p = SYSCALLS.get(), new_path_p = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'old_path_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var old_path = h.slice(ptr, ptr+i);

        ho = [{{{ heapAndOffset('HEAPU8', 'new_path_p') }}}];
        h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var new_path = h.slice(ptr, ptr+i);

        var done = function(result) {
          resume(function() {
            return result;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'rename', [old_path, new_path]);
      });
#else
      var SYS_RENAME = 38;
      var old_path = SYSCALLS.get(), new_path = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_RENAME, old_path, new_path);
#endif
    }
#endif
    var old_path = SYSCALLS.getStr(), new_path = SYSCALLS.getStr();
    FS.rename(old_path, new_path);
    return 0;
  },
  __syscall39: function(which, varargs) { // mkdir
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get(), mode = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(result) {
          resume(function() {
            return result;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'mkdir', [pathname, mode]);
      });
#else
      var SYS_MKDIR = 39;
      var path = SYSCALLS.get(), mode = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_MKDIR, path, mode);
#endif
    }
#endif
    var path = SYSCALLS.getStr(), mode = SYSCALLS.get();
    return SYSCALLS.doMkdir(path, mode);
  },
  __syscall40: function(which, varargs) { // rmdir
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(result) {
          resume(function() {
            return result;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'rmdir', [pathname]);
      });
#else
      var SYS_RMDIR = 39;
      var path = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_RMDIR, path);
#endif
    }
#endif
    var path = SYSCALLS.getStr();
    FS.rmdir(path);
    return 0;
  },
  __syscall41: function(which, varargs) { // dup
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd1 = SYSCALLS.get();

        var done = function(result) {
          resume(function() {
            return result|0;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'dup', [fd1]);
      });
#else
      var SYS_DUP = 41;
      var fd1 = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_DUP, fd1);
#endif
    }
#endif
    var old = SYSCALLS.getStreamFromFD();
    return FS.open(old.path, old.flags, 0).fd;
  },
  __syscall42: function(which, varargs) { // pipe
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pipefd = SYSCALLS.get();
        var done = function(err, fd1, fd2) {
          if (!err) {
            HEAP32[(pipefd>>2)] = fd1;
            HEAP32[(pipefd>>2)+1] = fd2;
          }
          resume(function() {
            return err || 0;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'pipe2', [0]);
      });
#else
      var SYS_PIPE2 = 41;
      var pipefd = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_PIPE2, pipefd, 0);
#endif
    }
#endif
    return -ERRNO_CODES.ENOSYS; // unsupported features
  },
  __syscall51: function(which, varargs) { // acct
    return -ERRNO_CODES.ENOSYS; // unsupported features
  },
  __syscall54: function(which, varargs) { // ioctl
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd = SYSCALLS.get(), op = SYSCALLS.get();

        var done = function(result) {
          resume(function() {
            return result|0;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'ioctl', [fd, op]);
      });
#else
      var SYS_IOCTL = 54;
      var fd = SYSCALLS.get(), op = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_IOCTL, fd, op);
#endif
    }
#endif
#if NO_FILESYSTEM
#if SYSCALL_DEBUG
    Module.printErr('no-op in ioctl syscall due to NO_FILESYSTEM');
#endif
    return 0;
#else
    var stream = SYSCALLS.getStreamFromFD(), op = SYSCALLS.get();
    switch (op) {
      case {{{ cDefine('TCGETS') }}}: {
        if (!stream.tty) return -ERRNO_CODES.ENOTTY;
#if SYSCALL_DEBUG
        Module.printErr('warning: not filling tio struct');
#endif
        return 0;
      }
      case {{{ cDefine('TCSETS') }}}: {
        if (!stream.tty) return -ERRNO_CODES.ENOTTY;
        return 0; // no-op, not actually adjusting terminal settings
      }
      case {{{ cDefine('TIOCGPGRP') }}}: {
        if (!stream.tty) return -ERRNO_CODES.ENOTTY;
        var argp = SYSCALLS.get();
        {{{ makeSetValue('argp', 0, 0, 'i32') }}};
        return 0;
      }
      case {{{ cDefine('TIOCSPGRP') }}}: {
        if (!stream.tty) return -ERRNO_CODES.ENOTTY;
        return -ERRNO_CODES.EINVAL; // not supported
      }
      case {{{ cDefine('FIONREAD') }}}: {
        var argp = SYSCALLS.get();
        return FS.ioctl(stream, op, argp);
      }
      default: abort('bad ioctl syscall ' + op);
    }
#endif // NO_FILESYSTEM
  },
  __syscall57__deps: ['$PROCINFO'],
  __syscall57: function(which, varargs) { // setpgid
    var pid = SYSCALLS.get(), pgid = SYSCALLS.get();
    if (pid && pid !== PROCINFO.pid) return -ERRNO_CODES.ESRCH;
    if (pgid && pgid !== PROCINFO.pgid) return -ERRNO_CODES.EPERM;
    return 0;
  },
  __syscall60: function(which, varargs) { // umask
    var mask = SYSCALLS.get();
    var old = SYSCALLS.umask;
    SYSCALLS.umask = mask;
    return old;
  },
  __syscall63: function(which, varargs) { // dup2
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd1 = SYSCALLS.get(), fd2 = SYSCALLS.get();

        var done = function(result) {
          resume(function() {
            return result|0;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'dup3', [fd1, fd2, 0]);
      });
#else
      var SYS_DUP3 = 330;
      var fd1 = SYSCALLS.get(), fd2 = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_DUP3, fd1, fd2, 0);
#endif
    }
#endif
    var old = SYSCALLS.getStreamFromFD(), suggestFD = SYSCALLS.get();
    if (old.fd === suggestFD) return suggestFD;
    return SYSCALLS.doDup(old.path, old.flags, suggestFD);
  },
  __syscall64__deps: ['$PROCINFO'],
  __syscall64: function(which, varargs) { // getppid
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var done = function(err, pid) {
          resume(function() {
            return err ? (err|0) : pid;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'getppid');
      });
#else
      var SYS_GETPPID = 64;
      return BROWSIX.browsix.syscall.sync(SYS_GETPPID);
#endif
    }
#endif
    return PROCINFO.ppid;
  },
  __syscall65__deps: ['$PROCINFO'],
  __syscall65: function(which, varargs) { // getpgrp
    return PROCINFO.pgid;
  },
  __syscall66: function(which, varargs) { // setsid
    return 0; // no-op
  },
  __syscall75: function(which, varargs) { // setrlimit
    return 0; // no-op
  },
  __syscall77: function(which, varargs) { // getrusage
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var who = SYSCALLS.get(), usage = SYSCALLS.get();
    _memset(usage, 0, {{{ C_STRUCTS.rusage.__size__ }}});
    {{{ makeSetValue('usage', C_STRUCTS.rusage.ru_utime.tv_sec, '1', 'i32') }}}; // fake some values
    {{{ makeSetValue('usage', C_STRUCTS.rusage.ru_utime.tv_usec, '2', 'i32') }}};
    {{{ makeSetValue('usage', C_STRUCTS.rusage.ru_stime.tv_sec, '3', 'i32') }}};
    {{{ makeSetValue('usage', C_STRUCTS.rusage.ru_stime.tv_usec, '4', 'i32') }}};
    return 0;
  },
  __syscall83: function(which, varargs) { // symlink
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: symlink');
      abort('unsupported syscall symlink');
      return 0;
    }
#endif
    var target = SYSCALLS.getStr(), linkpath = SYSCALLS.getStr();
    FS.symlink(target, linkpath);
    return 0;
  },
  __syscall85: function(which, varargs) { // readlink
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: readlink');
      abort('unsupported syscall readlink');
      return 0;
    }
#endif
    var path = SYSCALLS.getStr(), buf = SYSCALLS.get(), bufsize = SYSCALLS.get();
    return SYSCALLS.doReadlink(path, buf, bufsize);
  },
  __syscall91: function(which, varargs) { // munmap
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: munmap');
      abort('unsupported syscall munmap');
    }
#endif
    var addr = SYSCALLS.get(), len = SYSCALLS.get();
    // TODO: support unmmap'ing parts of allocations
    var info = SYSCALLS.mappings[addr];
    if (!info) return 0;
    if (len === info.len) {
      var stream = FS.getStream(info.fd);
      SYSCALLS.doMsync(addr, stream, len, info.flags)
      FS.munmap(stream);
      SYSCALLS.mappings[addr] = null;
      if (info.allocated) {
        _free(info.malloc);
      }
    }
    return 0;
  },
  __syscall94: function(which, varargs) { // fchmod
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: fchmod');
      //abort('unsupported syscall fchmod');
      return 0;
    }
#endif
    var fd = SYSCALLS.get(), mode = SYSCALLS.get();
    FS.fchmod(fd, mode);
    return 0;
  },
  __syscall96: function(which, varargs) { // getpriority
    return 0;
  },
  __syscall97: function(which, varargs) { // setpriority
    return -ERRNO_CODES.EPERM;
  },
  __syscall102__deps: ['$SOCKFS', '$DNS', '_read_sockaddr', '_write_sockaddr'],
  __syscall102: function(which, varargs) { // socketcall
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {

        var call = SYSCALLS.get(), socketvararg = SYSCALLS.get();
        // socketcalls pass the rest of the arguments in a struct
        SYSCALLS.varargs = socketvararg;
        switch (call) {
        case 1: { // socket
          var domain = SYSCALLS.get(), type = SYSCALLS.get(), protocol = SYSCALLS.get();
          var done = function(err, fd) {
            resume(function() {
              return err ? err : fd;
            });
          };
          BROWSIX.browsix.syscall.syscallAsync(done, 'socket', [domain, type, protocol]);
          break;
        }
        case 2: { // bind
          var sock = SYSCALLS.get(), addrp = SYSCALLS.get(), addrlen = SYSCALLS.get();
          var ho = [{{{ heapAndOffset('HEAPU8', 'addrp') }}}];
          var h = ho[0], off = ho[1];

          var done = function(err) {
            resume(function() {
              return err;
            });
          };
          BROWSIX.browsix.syscall.syscallAsync(done, 'bind', [sock, h.slice(off, off+addrlen)]);
          break;
        }
        case 3: { // connect
          var sock = SYSCALLS.get(), addrp = SYSCALLS.get(), addrlen = SYSCALLS.get();
          var ho = [{{{ heapAndOffset('HEAPU8', 'addrp') }}}];
          var h = ho[0], off = ho[1];
          var done = function(err) {
            resume(function() {
              return err;
            });
          };
          BROWSIX.browsix.syscall.syscallAsync(done, 'connect', [sock, h.slice(off, off+addrlen)]);
          return 0;
        }
        case 4: { // listen
          var sock = SYSCALLS.get(), backlog = SYSCALLS.get();
          var done = function(err) {
            resume(function() {
              return err;
            });
          };
          BROWSIX.browsix.syscall.syscallAsync(done, 'listen', [sock, backlog]);
          break;
        }
        case 5: { // accept
          var sock = SYSCALLS.get(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
          var ho = [{{{ heapAndOffset('HEAPU8', 'addr') }}}];
          var h = ho[0], off = ho[1];

          var done = function(err, fd, clientaddr) {
            if (!err) {
              h.subarray(off, off+addrlen).set(clientaddr);
            }

            resume(function() {
              return err ? (err|0) : fd;
            });
          };
          BROWSIX.browsix.syscall.syscallAsync(done, 'accept', [sock]);
          break;
        }
        case 6: { // getsockname
          var sock = SYSCALLS.get(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
          // TODO: sock.saddr should never be undefined, see TODO in websocket_sock_ops.getname
          var res = __write_sockaddr(addr, sock.family, DNS.lookup_name(sock.saddr || '0.0.0.0'), sock.sport);
          assert(!res.errno);
          return 0;
        }
        case 7: { // getpeername
          var sock = SYSCALLS.get(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
          if (!sock.daddr) {
            return -ERRNO_CODES.ENOTCONN; // The socket is not connected.
          }
          var res = __write_sockaddr(addr, sock.family, DNS.lookup_name(sock.daddr), sock.dport);
          assert(!res.errno);
          return 0;
        }
        case 11: { // sendto
          var sock = SYSCALLS.get(), msg = SYSCALLS.get(), length = SYSCALLS.get(), flags = SYSCALLS.get(), dest = SYSCALLS.get();
          var ho = [{{{ heapAndOffset('HEAPU8', 'msg') }}}];
          var h = ho[0], off = ho[1];
          if (!dest) {
            if (flags) {
              console.log('TODO: flags');
            }
            var done = function(err, n) {
              resume(function() {
                return err ? (err|0) : n;
              });
            };
            BROWSIX.browsix.syscall.syscallAsync(done, 'pwrite', [sock, h.slice(off, off+length), -1]);
          } else {
            // sendto an address
            console.log('TODO: datagram sendto not implemented');
            debugger;
            resume(function() {
              return -ERRNO_CODES.ENOSYS;
            });
            //return sock.sock_ops.sendmsg(sock, {{{ heapAndOffset('HEAP8', 'message') }}}, length, dest.addr, dest.port);
          }
          break;
        }
        case 12: { // recvfrom
          var sock = SYSCALLS.get(), buf = SYSCALLS.get(), len = SYSCALLS.get(), flags = SYSCALLS.get(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
          var msg = sock.sock_ops.recvmsg(sock, len);
          if (!msg) return 0; // socket is closed
          if (addr) {
            var res = __write_sockaddr(addr, sock.family, DNS.lookup_name(msg.addr), msg.port);
            assert(!res.errno);
          }
          HEAPU8.set(msg.buffer, buf);
          return msg.buffer.byteLength;
        }
        case 14: { // setsockopt
          console.log('FIXME: setsockopt');
          resume(function() {
            return 0;
          });
          break;
          //return -ERRNO_CODES.ENOPROTOOPT; // The option is unknown at the level indicated.
        }
        case 15: { // getsockopt
          var sock = SYSCALLS.get(), level = SYSCALLS.get(), optname = SYSCALLS.get(), optval = SYSCALLS.get(), optlen = SYSCALLS.get();
          // Minimal getsockopt aimed at resolving https://github.com/kripken/emscripten/issues/2211
          // so only supports SOL_SOCKET with SO_ERROR.
          if (level === {{{ cDefine('SOL_SOCKET') }}}) {
            if (optname === {{{ cDefine('SO_ERROR') }}}) {
              {{{ makeSetValue('optval', 0, 'sock.error', 'i32') }}};
              {{{ makeSetValue('optlen', 0, 4, 'i32') }}};
              sock.error = null; // Clear the error (The SO_ERROR option obtains and then clears this field).
              return 0;
            }
          }
          return -ERRNO_CODES.ENOPROTOOPT; // The option is unknown at the level indicated.
        }
        case 16: { // sendmsg
          var sock = SYSCALLS.getSocketFromFD(), message = SYSCALLS.get(), flags = SYSCALLS.get();
          var iov = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iov, '*') }}};
          var num = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iovlen, 'i32') }}};
          // read the address and port to send to
          var addr, port;
          var name = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_name, '*') }}};
          var namelen = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_namelen, 'i32') }}};
          if (name) {
            var info = __read_sockaddr(name, namelen);
            if (info.errno) return -info.errno;
            port = info.port;
            addr = DNS.lookup_addr(info.addr) || info.addr;
          }
          // concatenate scatter-gather arrays into one message buffer
          var total = 0;
          for (var i = 0; i < num; i++) {
            total += {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
          }
          var view = new Uint8Array(total);
          var offset = 0;
          for (var i = 0; i < num; i++) {
            var iovbase = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_base, 'i8*') }}};
            var iovlen = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
            for (var j = 0; j < iovlen; j++) {
              view[offset++] = {{{ makeGetValue('iovbase', 'j', 'i8') }}};
            }
          }
          // write the buffer
          return sock.sock_ops.sendmsg(sock, view, 0, total, addr, port);
        }
        case 17: { // recvmsg
          var sock = SYSCALLS.getSocketFromFD(), message = SYSCALLS.get(), flags = SYSCALLS.get();
          var iov = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iov, 'i8*') }}};
          var num = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iovlen, 'i32') }}};
          // get the total amount of data we can read across all arrays
          var total = 0;
          for (var i = 0; i < num; i++) {
            total += {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
          }
          // try to read total data
          var msg = sock.sock_ops.recvmsg(sock, total);
          if (!msg) return 0; // socket is closed

          // TODO honor flags:
          // MSG_OOB
          // Requests out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
          // MSG_PEEK
          // Peeks at the incoming message.
          // MSG_WAITALL
          // Requests that the function block until the full amount of data requested can be returned. The function may return a smaller amount of data if a signal is caught, if the connection is terminated, if MSG_PEEK was specified, or if an error is pending for the socket.

          // write the source address out
          var name = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_name, '*') }}};
          if (name) {
            var res = __write_sockaddr(name, sock.family, DNS.lookup_name(msg.addr), msg.port);
            assert(!res.errno);
          }
          // write the buffer out to the scatter-gather arrays
          var bytesRead = 0;
          var bytesRemaining = msg.buffer.byteLength;
          for (var i = 0; bytesRemaining > 0 && i < num; i++) {
            var iovbase = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_base, 'i8*') }}};
            var iovlen = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
            if (!iovlen) {
              continue;
            }
            var length = Math.min(iovlen, bytesRemaining);
            var buf = msg.buffer.subarray(bytesRead, bytesRead + length);
            HEAPU8.set(buf, iovbase + bytesRead);
            bytesRead += length;
            bytesRemaining -= length;
          }

          // TODO set msghdr.msg_flags
          // MSG_EOR
          // End of record was received (if supported by the protocol).
          // MSG_OOB
          // Out-of-band data was received.
          // MSG_TRUNC
          // Normal data was truncated.
          // MSG_CTRUNC

          return bytesRead;
        }
        default: abort('unsupported socketcall syscall ' + call);
        }
      });
#else
      abort('TODO: socket calls not yet supported in sync mode');
#endif
    }
#endif
    var call = SYSCALLS.get(), socketvararg = SYSCALLS.get();
    // socketcalls pass the rest of the arguments in a struct
    SYSCALLS.varargs = socketvararg;
    switch (call) {
      case 1: { // socket
        var domain = SYSCALLS.get(), type = SYSCALLS.get(), protocol = SYSCALLS.get();
        var sock = SOCKFS.createSocket(domain, type, protocol);
        assert(sock.stream.fd < 64); // XXX ? select() assumes socket fd values are in 0..63
        return sock.stream.fd;
      }
      case 2: { // bind
        var sock = SYSCALLS.getSocketFromFD(), info = SYSCALLS.getSocketAddress();
        sock.sock_ops.bind(sock, info.addr, info.port);
        return 0;
      }
      case 3: { // connect
        var sock = SYSCALLS.getSocketFromFD(), info = SYSCALLS.getSocketAddress();
        sock.sock_ops.connect(sock, info.addr, info.port);
        return 0;
      }
      case 4: { // listen
        var sock = SYSCALLS.getSocketFromFD(), backlog = SYSCALLS.get();
        sock.sock_ops.listen(sock, backlog);
        return 0;
      }
      case 5: { // accept
        var sock = SYSCALLS.getSocketFromFD(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
        var newsock = sock.sock_ops.accept(sock);
        if (addr) {
          var res = __write_sockaddr(addr, newsock.family, DNS.lookup_name(newsock.daddr), newsock.dport);
          assert(!res.errno);
        }
        return newsock.stream.fd;
      }
      case 6: { // getsockname
        var sock = SYSCALLS.getSocketFromFD(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
        // TODO: sock.saddr should never be undefined, see TODO in websocket_sock_ops.getname
        var res = __write_sockaddr(addr, sock.family, DNS.lookup_name(sock.saddr || '0.0.0.0'), sock.sport);
        assert(!res.errno);
        return 0;
      }
      case 7: { // getpeername
        var sock = SYSCALLS.getSocketFromFD(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
        if (!sock.daddr) {
          return -ERRNO_CODES.ENOTCONN; // The socket is not connected.
        }
        var res = __write_sockaddr(addr, sock.family, DNS.lookup_name(sock.daddr), sock.dport);
        assert(!res.errno);
        return 0;
      }
      case 11: { // sendto
        var sock = SYSCALLS.getSocketFromFD(), message = SYSCALLS.get(), length = SYSCALLS.get(), flags = SYSCALLS.get(), dest = SYSCALLS.getSocketAddress(true);
        if (!dest) {
          // send, no address provided
          return FS.write(sock.stream, {{{ heapAndOffset('HEAP8', 'message') }}}, length);
        } else {
          // sendto an address
          return sock.sock_ops.sendmsg(sock, {{{ heapAndOffset('HEAP8', 'message') }}}, length, dest.addr, dest.port);
        }
      }
      case 12: { // recvfrom
        var sock = SYSCALLS.getSocketFromFD(), buf = SYSCALLS.get(), len = SYSCALLS.get(), flags = SYSCALLS.get(), addr = SYSCALLS.get(), addrlen = SYSCALLS.get();
        var msg = sock.sock_ops.recvmsg(sock, len);
        if (!msg) return 0; // socket is closed
        if (addr) {
          var res = __write_sockaddr(addr, sock.family, DNS.lookup_name(msg.addr), msg.port);
          assert(!res.errno);
        }
        HEAPU8.set(msg.buffer, buf);
        return msg.buffer.byteLength;
      }
      case 14: { // setsockopt
        return -ERRNO_CODES.ENOPROTOOPT; // The option is unknown at the level indicated.
      }
      case 15: { // getsockopt
        var sock = SYSCALLS.getSocketFromFD(), level = SYSCALLS.get(), optname = SYSCALLS.get(), optval = SYSCALLS.get(), optlen = SYSCALLS.get();
        // Minimal getsockopt aimed at resolving https://github.com/kripken/emscripten/issues/2211
        // so only supports SOL_SOCKET with SO_ERROR.
        if (level === {{{ cDefine('SOL_SOCKET') }}}) {
          if (optname === {{{ cDefine('SO_ERROR') }}}) {
            {{{ makeSetValue('optval', 0, 'sock.error', 'i32') }}};
            {{{ makeSetValue('optlen', 0, 4, 'i32') }}};
            sock.error = null; // Clear the error (The SO_ERROR option obtains and then clears this field).
            return 0;
          }
        }
        return -ERRNO_CODES.ENOPROTOOPT; // The option is unknown at the level indicated.
      }
      case 16: { // sendmsg
        var sock = SYSCALLS.getSocketFromFD(), message = SYSCALLS.get(), flags = SYSCALLS.get();
        var iov = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iov, '*') }}};
        var num = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iovlen, 'i32') }}};
        // read the address and port to send to
        var addr, port;
        var name = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_name, '*') }}};
        var namelen = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_namelen, 'i32') }}};
        if (name) {
          var info = __read_sockaddr(name, namelen);
          if (info.errno) return -info.errno;
          port = info.port;
          addr = DNS.lookup_addr(info.addr) || info.addr;
        }
        // concatenate scatter-gather arrays into one message buffer
        var total = 0;
        for (var i = 0; i < num; i++) {
          total += {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
        }
        var view = new Uint8Array(total);
        var offset = 0;
        for (var i = 0; i < num; i++) {
          var iovbase = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_base, 'i8*') }}};
          var iovlen = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
          for (var j = 0; j < iovlen; j++) {  
            view[offset++] = {{{ makeGetValue('iovbase', 'j', 'i8') }}};
          }
        }
        // write the buffer
        return sock.sock_ops.sendmsg(sock, view, 0, total, addr, port);
      }
      case 17: { // recvmsg
        var sock = SYSCALLS.getSocketFromFD(), message = SYSCALLS.get(), flags = SYSCALLS.get();
        var iov = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iov, 'i8*') }}};
        var num = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_iovlen, 'i32') }}};
        // get the total amount of data we can read across all arrays
        var total = 0;
        for (var i = 0; i < num; i++) {
          total += {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
        }
        // try to read total data
        var msg = sock.sock_ops.recvmsg(sock, total);
        if (!msg) return 0; // socket is closed

        // TODO honor flags:
        // MSG_OOB
        // Requests out-of-band data. The significance and semantics of out-of-band data are protocol-specific.
        // MSG_PEEK
        // Peeks at the incoming message.
        // MSG_WAITALL
        // Requests that the function block until the full amount of data requested can be returned. The function may return a smaller amount of data if a signal is caught, if the connection is terminated, if MSG_PEEK was specified, or if an error is pending for the socket.

        // write the source address out
        var name = {{{ makeGetValue('message', C_STRUCTS.msghdr.msg_name, '*') }}};
        if (name) {
          var res = __write_sockaddr(name, sock.family, DNS.lookup_name(msg.addr), msg.port);
          assert(!res.errno);
        }
        // write the buffer out to the scatter-gather arrays
        var bytesRead = 0;
        var bytesRemaining = msg.buffer.byteLength;
        for (var i = 0; bytesRemaining > 0 && i < num; i++) {
          var iovbase = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_base, 'i8*') }}};
          var iovlen = {{{ makeGetValue('iov', '(' + C_STRUCTS.iovec.__size__ + ' * i) + ' + C_STRUCTS.iovec.iov_len, 'i32') }}};
          if (!iovlen) {
            continue;
          }
          var length = Math.min(iovlen, bytesRemaining);
          var buf = msg.buffer.subarray(bytesRead, bytesRead + length);
          HEAPU8.set(buf, iovbase + bytesRead);
          bytesRead += length;
          bytesRemaining -= length;
        }

        // TODO set msghdr.msg_flags
        // MSG_EOR
        // End of record was received (if supported by the protocol).
        // MSG_OOB
        // Out-of-band data was received.
        // MSG_TRUNC
        // Normal data was truncated.
        // MSG_CTRUNC

        return bytesRead;
      }
      default: abort('unsupported socketcall syscall ' + call);
    }
  },
  __syscall104: function(which, varargs) { // setitimer
    return -ERRNO_CODES.ENOSYS; // unsupported feature
  },
  __syscall114: function(which, varargs) { // wait4
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pid = SYSCALLS.get(), wstatus = SYSCALLS.get(), options = SYSCALLS.get(), rusage = SYSCALLS.get();

        var done = function(ret, wstatusIn, rusageIn) {
          if (wstatus) {
            HEAP32[wstatus>>2] = wstatusIn;
          }
          if (rusageIn) {
            console.log('FIXME: wait4 rusage');
          }

          resume(function() {
            return ret;
          });
        };
        var sys_name = 'wait4';
        var args = [pid, options];
        BROWSIX.browsix.syscall.syscallAsync(done, sys_name, args);
      });
#else
      var SYS_WAIT4 = 114;
      var pid = SYSCALLS.get(), wstatus = SYSCALLS.get(), options = SYSCALLS.get(), rusage = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_WAIT4, pid, wstatus, options, rusage);
#endif
    }
#endif
    abort('cannot wait on child processes');
  },
#if EMTERPRETIFY_ASYNC
  __syscall118__deps: ['$EmterpreterAsync'],
#endif
  __syscall118: function(which, varargs) { // fsync
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: fsync');
      return 0;
    }
#endif
    var stream = SYSCALLS.getStreamFromFD();
#if EMTERPRETIFY_ASYNC
    return EmterpreterAsync.handle(function(resume) {
      var mount = stream.node.mount;
      if (!mount.type.syncfs) {
        // We write directly to the file system, so there's nothing to do here.
        resume(function() { return 0 });
        return;
      }
      mount.type.syncfs(mount, false, function(err) {
        if (err) {
          resume(function() { return -ERRNO_CODES.EIO });
          return;
        }
        resume(function() { return 0 });
      });
    });
#else
    return 0; // we can't do anything synchronously; the in-memory FS is already synced to
#endif
  },
  __syscall121: function(which, varargs) { // setdomainname
    return -ERRNO_CODES.EPERM;
  },
  __syscall122: function(which, varargs) { // uname
    var buf = SYSCALLS.get();
    if (!buf) return -ERRNO_CODES.EFAULT
    var layout = {{{ JSON.stringify(C_STRUCTS.utsname) }}};
    function copyString(element, value) {
      var offset = layout[element];
      writeAsciiToMemory(value, buf + offset);
    }
    copyString('sysname', 'Emscripten');
    copyString('nodename', 'emscripten');
    copyString('release', '1.0');
    copyString('version', '#1');
    copyString('machine', 'x86-JS');
    return 0;
  },
  __syscall125: function(which, varargs) { // mprotect
    return 0; // let's not and say we did
  },
  __syscall132__deps: ['$PROCINFO'],
  __syscall132: function(which, varargs) { // getpgid
    var pid = SYSCALLS.get();
    if (pid && pid !== PROCINFO.pid) return -ERRNO_CODES.ESRCH;
    return PROCINFO.pgid;
  },
  __syscall133: function(which, varargs) { // fchdir
    var stream = SYSCALLS.getStreamFromFD();
    FS.chdir(stream.path);
    return 0;
  },
  __syscall140: function(which, varargs) { // llseek
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd = SYSCALLS.get(), offset_high = SYSCALLS.get(), offset_low = SYSCALLS.get(), result = SYSCALLS.get(), whence = SYSCALLS.get();
        assert(offset_high === 0);

        var done = function(err, off) {
          if (!err) {
            {{{ makeSetValue('result', '0', 'off', 'i32') }}};
          }
          resume(function() {
            return err;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'llseek', [fd, offset_high, offset_low, whence]);
    });
#else
      var SYS_LLSEEK = 140;
      var fd = SYSCALLS.get(), offhi = SYSCALLS.get(), offlo = SYSCALLS.get(), result = SYSCALLS.get(), whence = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_LLSEEK, fd, offhi, offlo, result, whence);
#endif
    }
#endif
    var stream = SYSCALLS.getStreamFromFD(), offset_high = SYSCALLS.get(), offset_low = SYSCALLS.get(), result = SYSCALLS.get(), whence = SYSCALLS.get();
    var offset = offset_low;
    assert(offset_high === 0);
    FS.llseek(stream, offset, whence);
    {{{ makeSetValue('result', '0', 'stream.position', 'i32') }}};
    if (stream.getdents && offset === 0 && whence === {{{ cDefine('SEEK_SET') }}}) stream.getdents = null; // reset readdir state
    return 0;
  },
  __syscall142: function(which, varargs) { // newselect
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      abort('newselect not implemented');
      return;
    }
#endif
    // readfds are supported,
    // writefds checks socket open status
    // exceptfds not supported
    // timeout is always 0 - fully async
    var nfds = SYSCALLS.get(), readfds = SYSCALLS.get(), writefds = SYSCALLS.get(), exceptfds = SYSCALLS.get(), timeout = SYSCALLS.get();

    assert(nfds <= 64, 'nfds must be less than or equal to 64');  // fd sets have 64 bits // TODO: this could be 1024 based on current musl headers
    assert(!exceptfds, 'exceptfds not supported');

    var total = 0;
    
    var srcReadLow = (readfds ? {{{ makeGetValue('readfds', 0, 'i32') }}} : 0),
        srcReadHigh = (readfds ? {{{ makeGetValue('readfds', 4, 'i32') }}} : 0);
    var srcWriteLow = (writefds ? {{{ makeGetValue('writefds', 0, 'i32') }}} : 0),
        srcWriteHigh = (writefds ? {{{ makeGetValue('writefds', 4, 'i32') }}} : 0);
    var srcExceptLow = (exceptfds ? {{{ makeGetValue('exceptfds', 0, 'i32') }}} : 0),
        srcExceptHigh = (exceptfds ? {{{ makeGetValue('exceptfds', 4, 'i32') }}} : 0);

    var dstReadLow = 0,
        dstReadHigh = 0;
    var dstWriteLow = 0,
        dstWriteHigh = 0;
    var dstExceptLow = 0,
        dstExceptHigh = 0;

    var allLow = (readfds ? {{{ makeGetValue('readfds', 0, 'i32') }}} : 0) |
                 (writefds ? {{{ makeGetValue('writefds', 0, 'i32') }}} : 0) |
                 (exceptfds ? {{{ makeGetValue('exceptfds', 0, 'i32') }}} : 0);
    var allHigh = (readfds ? {{{ makeGetValue('readfds', 4, 'i32') }}} : 0) |
                  (writefds ? {{{ makeGetValue('writefds', 4, 'i32') }}} : 0) |
                  (exceptfds ? {{{ makeGetValue('exceptfds', 4, 'i32') }}} : 0);

    function check(fd, low, high, val) {
      return (fd < 32 ? (low & val) : (high & val));
    }

    for (var fd = 0; fd < nfds; fd++) {
      var mask = 1 << (fd % 32);
      if (!(check(fd, allLow, allHigh, mask))) {
        continue;  // index isn't in the set
      }

      var stream = FS.getStream(fd);
      if (!stream) throw new FS.ErrnoError(ERRNO_CODES.EBADF);

      var flags = SYSCALLS.DEFAULT_POLLMASK;

      if (stream.stream_ops.poll) {
        flags = stream.stream_ops.poll(stream);
      }

      if ((flags & {{{ cDefine('POLLIN') }}}) && check(fd, srcReadLow, srcReadHigh, mask)) {
        fd < 32 ? (dstReadLow = dstReadLow | mask) : (dstReadHigh = dstReadHigh | mask);
        total++;
      }
      if ((flags & {{{ cDefine('POLLOUT') }}}) && check(fd, srcWriteLow, srcWriteHigh, mask)) {
        fd < 32 ? (dstWriteLow = dstWriteLow | mask) : (dstWriteHigh = dstWriteHigh | mask);
        total++;
      }
      if ((flags & {{{ cDefine('POLLPRI') }}}) && check(fd, srcExceptLow, srcExceptHigh, mask)) {
        fd < 32 ? (dstExceptLow = dstExceptLow | mask) : (dstExceptHigh = dstExceptHigh | mask);
        total++;
      }
    }

    if (readfds) {
      {{{ makeSetValue('readfds', '0', 'dstReadLow', 'i32') }}};
      {{{ makeSetValue('readfds', '4', 'dstReadHigh', 'i32') }}};
    }
    if (writefds) {
      {{{ makeSetValue('writefds', '0', 'dstWriteLow', 'i32') }}};
      {{{ makeSetValue('writefds', '4', 'dstWriteHigh', 'i32') }}};
    }
    if (exceptfds) {
      {{{ makeSetValue('exceptfds', '0', 'dstExceptLow', 'i32') }}};
      {{{ makeSetValue('exceptfds', '4', 'dstExceptHigh', 'i32') }}};
    }
    
    return total;
  },
  __syscall144: function(which, varargs) { // msync
    var addr = SYSCALLS.get(), len = SYSCALLS.get(), flags = SYSCALLS.get();
    var info = SYSCALLS.mappings[addr];
    if (!info) return 0;
    SYSCALLS.doMsync(addr, FS.getStream(info.fd), len, info.flags);
    return 0;
  },
  __syscall145: function(which, varargs) { // readv
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {

        var fd = SYSCALLS.get(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();

        bufs = [];
        for (var i = 0; i < iovcnt; i++) {
          var ptr = {{{ makeGetValue('iov', 'i*8', 'i32') }}};
          var len = {{{ makeGetValue('iov', 'i*8 + 4', 'i32') }}};
          if (len === 0)
            continue;
          bufs.push(HEAPU8.subarray(ptr, ptr+len));
        }

        if (!bufs.length) {
          return resume(function() {
            console.log('readv early 0');
            return 0;
          });
        }

        var lenRead = 0;

        function readOne() {
          var buf = bufs.shift();
          var done = function(err, len, data) {

            if (!err) {
              lenRead += len;
              buf.set(data);
            }

            if (bufs.length) {
              readOne();
            } else {
              resume(function() {
                return err ? err : lenRead;
              });
            }
          };
          BROWSIX.browsix.syscall.syscallAsync(done, 'pread', [fd, buf.length, -1]);
        }
        readOne();
      });
#else
      var SYS_READ = 3;
      var fd = SYSCALLS.get(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();
      var ret = 0;
      for (var i = 0; i < iovcnt; i++) {
        var ptr = {{{ makeGetValue('iov', 'i*8', 'i32') }}};
        var len = {{{ makeGetValue('iov', 'i*8 + 4', 'i32') }}};
        if (len === 0)
          continue;
        var read = BROWSIX.browsix.syscall.sync(SYS_READ, fd, ptr, len);
        if (read < 0)
          return ret === 0 ? read : ret;
        ret += read;
      }
      return ret;
#endif
    }
#endif
    var stream = SYSCALLS.getStreamFromFD(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();
    return SYSCALLS.doReadv(stream, iov, iovcnt);
  },
  __syscall146: function(which, varargs) { // writev
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {

        var fd = SYSCALLS.get(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();

        bufs = [];
        for (var i = 0; i < iovcnt; i++) {
          var ptr = {{{ makeGetValue('iov', 'i*8', 'i32') }}};
          var len = {{{ makeGetValue('iov', 'i*8 + 4', 'i32') }}};
          if (len === 0)
            continue;
          bufs.push(HEAPU8.slice(ptr, ptr+len));
        }

        if (!bufs.length) {
          return resume(function() {
            return 0;
          });
        }

        var written = 0;

        function writeOne() {
          var buf = bufs.shift();
          var done = function(err, len) {
            if (!err)
              written += len;

            if (bufs.length) {
              writeOne();
            } else {
              resume(function() {
                return err ? err : written;
              });
            }
          };
          BROWSIX.browsix.syscall.syscallAsync(done, 'pwrite', [fd, buf, -1]);
        }
        writeOne();
      });
#else
      var SYS_WRITE = 4;
      var fd = SYSCALLS.get(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();
      var ret = 0;
      for (var i = 0; i < iovcnt; i++) {
        var ptr = {{{ makeGetValue('iov', 'i*8', 'i32') }}};
        var len = {{{ makeGetValue('iov', 'i*8 + 4', 'i32') }}};
        if (len === 0)
          continue;
        var written = BROWSIX.browsix.syscall.sync(SYS_WRITE, fd, ptr, len);
        if (written < 0)
          return ret === 0 ? written : ret;
        ret += written;
      }
      return ret;
#endif
    }
#endif
#if NO_FILESYSTEM == 0
    var stream = SYSCALLS.getStreamFromFD(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();
    return SYSCALLS.doWritev(stream, iov, iovcnt);
#else
    // hack to support printf in NO_FILESYSTEM
    var stream = SYSCALLS.get(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get();
    var ret = 0;
    if (!___syscall146.buffer) {
      ___syscall146.buffers = [null, [], []]; // 1 => stdout, 2 => stderr
      ___syscall146.printChar = function(stream, curr) {
        var buffer = ___syscall146.buffers[stream];
        assert(buffer);
        if (curr === 0 || curr === {{{ charCode('\n') }}}) {
          (stream === 1 ? Module['print'] : Module['printErr'])(UTF8ArrayToString(buffer, 0));
          buffer.length = 0;
        } else {
          buffer.push(curr);
        }
      };
    }
    for (var i = 0; i < iovcnt; i++) {
      var ptr = {{{ makeGetValue('iov', 'i*8', 'i32') }}};
      var len = {{{ makeGetValue('iov', 'i*8 + 4', 'i32') }}};
      for (var j = 0; j < len; j++) {
        ___syscall146.printChar(stream, HEAPU8[ptr+j]);
      }
      ret += len;
    }
    return ret;
#endif // NO_FILESYSTEM == 0
  },
  __syscall147__deps: ['$PROCINFO'],
  __syscall147: function(which, varargs) { // getsid
    var pid = SYSCALLS.get();
    if (pid && pid !== PROCINFO.pid) return -ERRNO_CODES.ESRCH;
    return PROCINFO.sid;
  },
  __syscall148: function(which, varargs) { // fdatasync
    var stream = SYSCALLS.getStreamFromFD();
    return 0; // we can't do anything synchronously; the in-memory FS is already synced to
  },
  __syscall150: '__syscall153',     // mlock
  __syscall151: '__syscall153',     // munlock
  __syscall152: '__syscall153',     // mlockall
  __syscall153: function(which, varargs) { // munlockall
    return 0;
  },
  __syscall163: function(which, varargs) { // mremap
    return -ERRNO_CODES.ENOMEM; // never succeed
  },
  __syscall168: function(which, varargs) { // poll
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      abort('poll not implemented');
      return;
    }
#endif
    var fds = SYSCALLS.get(), nfds = SYSCALLS.get(), timeout = SYSCALLS.get();
    var nonzero = 0;
    for (var i = 0; i < nfds; i++) {
      var pollfd = fds + {{{ C_STRUCTS.pollfd.__size__ }}} * i;
      var fd = {{{ makeGetValue('pollfd', C_STRUCTS.pollfd.fd, 'i32') }}};
      var events = {{{ makeGetValue('pollfd', C_STRUCTS.pollfd.events, 'i16') }}};
      var mask = {{{ cDefine('POLLNVAL') }}};
      var stream = FS.getStream(fd);
      if (stream) {
        mask = SYSCALLS.DEFAULT_POLLMASK;
        if (stream.stream_ops.poll) {
          mask = stream.stream_ops.poll(stream);
        }
      }
      mask &= events | {{{ cDefine('POLLERR') }}} | {{{ cDefine('POLLHUP') }}};
      if (mask) nonzero++;
      {{{ makeSetValue('pollfd', C_STRUCTS.pollfd.revents, 'mask', 'i16') }}};
    }
    return nonzero;
  },
  __syscall174: function(which, varargs) { // rt_sigaction
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var signum = SYSCALLS.get(), act = SYSCALLS.get(), oldact = SYSCALLS.get();

        resume(function() {
          return 0;
        });

        // var done = function(ret, oldact) {
        //   resume(function() {
        //     return ret;
        //   });
        // };
        // BROWSIX.browsix.syscall.syscallAsync(done, 'sigaction', [signum, act, oldact]);;
      });
#else
      var SYS_SIGACTION = 174;
      var signum = SYSCALLS.get(), act = SYSCALLS.get(), oldact = SYSCALLS.get();

      // if act->sa_handler == SIG_DFL or SIG_IGN, pass along to
      // kernel.  otherwise, register the pointer here somewhere.  and
      // figure out how to invoke it?

      return BROWSIX.browsix.syscall.sync(SYS_SIGACTION, signum, act, oldact);
#endif
    }
#endif
    //console.log('TODO: sigaction');
    return 0;
  },
  __syscall175: function(which, varargs) { // rt_sigprocmask
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var how = SYSCALLS.get(), set = SYSCALLS.get(), oldset = SYSCALLS.get();

        resume(function() {
          return 0;
        });

        // var done = function(ret, oldset) {
        //   resume(function() {
        //     return ret;
        //   });
        // };
        // BROWSIX.browsix.syscall.syscallAsync(done, 'sigprocmask', [how, set, oldset]);;
      });
#else
      var SYS_SIGPROCMASK = 174;
      var how = SYSCALLS.get(), set = SYSCALLS.get(), oldset = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_SIGPROCMASK, how, set, oldset);
#endif
    }
#endif
    //console.log('TODO: sigprocmask');
    return 0;
  },
  __syscall180: function(which, varargs) { // pread64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: pread64');
      abort('unsupported syscall pread64');
    }
#endif
    var stream = SYSCALLS.getStreamFromFD(), buf = SYSCALLS.get(), count = SYSCALLS.get(), zero = SYSCALLS.getZero(), offset = SYSCALLS.get64();
    return FS.read(stream, {{{ heapAndOffset('HEAP8', 'buf') }}}, count, offset);
  },
  __syscall181: function(which, varargs) { // pwrite64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: pwrite64');
      abort('unsupported syscall pwrite64');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var stream = SYSCALLS.getStreamFromFD(), buf = SYSCALLS.get(), count = SYSCALLS.get(), zero = SYSCALLS.getZero(), offset = SYSCALLS.get64();
    return FS.write(stream, {{{ heapAndOffset('HEAP8', 'buf') }}}, nbyte, offset);
  },
  __syscall183: function(which, varargs) { // getcwd
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var buf = SYSCALLS.get(), size = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'buf') }}}];
        var h = ho[0], off = ho[1];

        var done = function(cwd) {
          var sa = h.subarray(off, off+size);
          var nullPos = cwd.byteLength;
          if (nullPos >= size)
            nullPos = size-1;

          sa.set(cwd);
          sa[nullPos] = 0;

          resume(function() {
            return buf;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'getcwd', []);;
      });
#else
      var SYS_GETCWD = 183;
      var buf = SYSCALLS.get(), size = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_GETCWD, buf, size);
#endif
    }
#endif
    var buf = SYSCALLS.get(), size = SYSCALLS.get();
    if (size === 0) return -ERRNO_CODES.EINVAL;
    var cwd = FS.cwd();
    if (size < cwd.length + 1) return -ERRNO_CODES.ERANGE;
    writeAsciiToMemory(cwd, buf);
    return buf;
  },
  __syscall191: function(which, varargs) { // ugetrlimit
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var resource = SYSCALLS.get(), rlim = SYSCALLS.get();
    {{{ makeSetValue('rlim', C_STRUCTS.rlimit.rlim_cur, '-1', 'i32') }}};  // RLIM_INFINITY
    {{{ makeSetValue('rlim', C_STRUCTS.rlimit.rlim_cur + 4, '-1', 'i32') }}};  // RLIM_INFINITY
    {{{ makeSetValue('rlim', C_STRUCTS.rlimit.rlim_max, '-1', 'i32') }}};  // RLIM_INFINITY
    {{{ makeSetValue('rlim', C_STRUCTS.rlimit.rlim_max + 4, '-1', 'i32') }}};  // RLIM_INFINITY
    return 0; // just report no limits
  },
  __syscall192: function(which, varargs) { // mmap2
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: mmap2');
      abort('unsupported syscall mmap2');
    }
#endif
    var addr = SYSCALLS.get(), len = SYSCALLS.get(), prot = SYSCALLS.get(), flags = SYSCALLS.get(), fd = SYSCALLS.get(), off = SYSCALLS.get()
    off <<= 12; // undo pgoffset
    var ptr;
    var allocated = false;
    if (fd === -1) {
      ptr = _malloc(len);
      if (!ptr) return -ERRNO_CODES.ENOMEM;
      _memset(ptr, 0, len);
      allocated = true;
    } else {
      var info = FS.getStream(fd);
      if (!info) return -ERRNO_CODES.EBADF;
      var res = FS.mmap(info, HEAPU8, addr, len, off, prot, flags);
      ptr = res.ptr;
      allocated = res.allocated;
    }
    SYSCALLS.mappings[ptr] = { malloc: ptr, len: len, allocated: allocated, fd: fd, flags: flags };
    return ptr;
  },
  __syscall193: function(which, varargs) { // truncate64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: truncate64');
      abort('unsupported syscall truncate64');
    }
#endif
    var path = SYSCALLS.getStr(), zero = SYSCALLS.getZero(), length = SYSCALLS.get64();
    FS.truncate(path, length);
    return 0;
  },
  __syscall194: function(which, varargs) { // ftruncate64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: ftruncate64');
      abort('unsupported syscall ftruncate64');
    }
#endif
    var fd = SYSCALLS.get(), zero = SYSCALLS.getZero(), length = SYSCALLS.get64();
    FS.ftruncate(fd, length);
    return 0;
  },
  __syscall195: function(which, varargs) { // SYS_stat64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get(), buf = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(err, stat) {
          if (!err) {
            HEAPU8.subarray(buf, buf+stat.byteLength).set(stat);
          }
          resume(function() {
            return err;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'stat', [pathname]);
    });
#else
      var SYS_STAT = 195;
      var path = SYSCALLS.get(), buf = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_STAT, path, buf);
#endif
    }
#endif
    var path = SYSCALLS.getStr(), buf = SYSCALLS.get();
    return SYSCALLS.doStat(FS.stat, path, buf);
  },
  __syscall196: function(which, varargs) { // SYS_lstat64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pathname_p = SYSCALLS.get(), buf = SYSCALLS.get();
        var ho = [{{{ heapAndOffset('HEAPU8', 'pathname_p') }}}];
        var h = ho[0], ptr = ho[1];

        var i = 0;
        var t;
        while (true) {
          t = {{{ makeGetValue('ptr', 'i', 'i8', 0, 1) }}};
          if (t === 0)
            break;
          i++;
        }
        var pathname = h.slice(ptr, ptr+i);

        var done = function(err, stat) {
          if (!err) {
            HEAPU8.subarray(buf, buf+stat.byteLength).set(stat);
          }
          resume(function() {
            return err;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'lstat', [pathname]);
    });
#else
      var SYS_LSTAT = 196;
      var path = SYSCALLS.get(), buf = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_LSTAT, path, buf);
#endif
    }
#endif
    var path = SYSCALLS.getStr(), buf = SYSCALLS.get();
    return SYSCALLS.doStat(FS.lstat, path, buf);
  },
  __syscall197: function(which, varargs) { // SYS_fstat64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd = SYSCALLS.get(), buf = SYSCALLS.get();

        var done = function(err, stat) {
          if (!err) {
            HEAPU8.subarray(buf, buf+stat.byteLength).set(stat);
          }
          resume(function() {
            return err;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'fstat', [fd]);
      });
#else
      var SYS_FSTAT64 = 197;
      var fd = SYSCALLS.get(), buf = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_FSTAT64, fd, buf);
#endif
    }
#endif
    var stream = SYSCALLS.getStreamFromFD(), buf = SYSCALLS.get();
    return SYSCALLS.doStat(FS.stat, stream.path, buf);
  },
  __syscall198: function(which, varargs) { // lchown32
    var path = SYSCALLS.getStr(), owner = SYSCALLS.get(), group = SYSCALLS.get();
    FS.chown(path, owner, group); // XXX we ignore the 'l' aspect, and do the same as chown
    return 0;
  },
  __syscall199: '__syscall202',     // getuid32
  __syscall200: '__syscall202',     // getgid32
  __syscall201: '__syscall202',     // geteuid32
  __syscall202: function(which, varargs) { // getgid32
    return 0;
  },
  __syscall207: function(which, varargs) { // fchown32
    var fd = SYSCALLS.get(), owner = SYSCALLS.get(), group = SYSCALLS.get();
    FS.fchown(fd, owner, group);
    return 0;
  },
  __syscall212: function(which, varargs) { // chown32
    var path = SYSCALLS.getStr(), owner = SYSCALLS.get(), group = SYSCALLS.get();
    FS.chown(path, owner, group);
    return 0;
  },
  __syscall203: '__syscall214',     // setreuid32
  __syscall204: '__syscall214',     // setregid32
  __syscall213: '__syscall214',     // setuid32
  __syscall214: function(which, varargs) { // setgid32
    var uid = SYSCALLS.get();
    if (uid !== 0) return -ERRNO_CODES.EPERM;
    return 0;
  },
  __syscall205: function(which, varargs) { // getgroups32
    var size = SYSCALLS.get(), list = SYSCALLS.get();
    if (size < 1) return -ERRNO_CODES.EINVAL;
    {{{ makeSetValue('list', '0', '0', 'i32') }}};
    return 1;
  },
  __syscall208: '__syscall210',     // setresuid32
  __syscall210: function(which, varargs) { // setresgid32
    var ruid = SYSCALLS.get(), euid = SYSCALLS.get(), suid = SYSCALLS.get();
    if (euid !== 0) return -ERRNO_CODES.EPERM;
    return 0;
  },
  __syscall209: '__syscall211',     // getresuid
  __syscall211: function(which, varargs) { // getresgid32
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var ruid = SYSCALLS.get(), euid = SYSCALLS.get(), suid = SYSCALLS.get();
    {{{ makeSetValue('ruid', '0', '0', 'i32') }}};
    {{{ makeSetValue('euid', '0', '0', 'i32') }}};
    {{{ makeSetValue('suid', '0', '0', 'i32') }}};
    return 0;
  },
  __syscall218: function(which, varargs) { // mincore
    return -ERRNO_CODES.ENOSYS; // unsupported feature
  },
  __syscall219: function(which, varargs) { // madvise
    return 0; // advice is welcome, but ignored
  },
  __syscall220: function(which, varargs) { // SYS_getdents64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd = SYSCALLS.get(), dirp = SYSCALLS.get(), count = SYSCALLS.get();

        var done = function(err, buf) {
          if (err > 0) {
            HEAPU8.subarray(dirp, dirp+buf.byteLength).set(buf);
          }
          resume(function() {
            return err;
          });
        };

        BROWSIX.browsix.syscall.syscallAsync(done, 'getdents', [fd, count]);
      });
#else
      var SYS_GETDENTS64 = 220;
      var fd = SYSCALLS.get(), dirp = SYSCALLS.get(), count = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_GETDENTS64, fd, dirp, count);
#endif
    }
#endif
    var stream = SYSCALLS.getStreamFromFD(), dirp = SYSCALLS.get(), count = SYSCALLS.get();
    if (!stream.getdents) {
      stream.getdents = FS.readdir(stream.path);
    }
    var pos = 0;
    while (stream.getdents.length > 0 && pos + {{{ C_STRUCTS.dirent.__size__ }}} < count) {
      var id;
      var type;
      var name = stream.getdents.pop();
      assert(name.length < 256); // limit of dirent struct
      if (name[0] === '.') {
        id = 1;
        type = 4; // DT_DIR
      } else {
        var child = FS.lookupNode(stream.node, name);
        id = child.id;
        type = FS.isChrdev(child.mode) ? 2 :  // DT_CHR, character device.
               FS.isDir(child.mode) ? 4 :     // DT_DIR, directory.
               FS.isLink(child.mode) ? 10 :   // DT_LNK, symbolic link.
               8;                             // DT_REG, regular file.
      }
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_ino, 'id', 'i32') }}};
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_off, 'stream.position', 'i32') }}};
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_reclen, C_STRUCTS.dirent.__size__, 'i16') }}};
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_type, 'type', 'i8') }}};
      for (var i = 0; i < name.length; i++) {
        {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_name + ' + i', 'name.charCodeAt(i)', 'i8') }}};
      }
      {{{ makeSetValue('dirp + pos', C_STRUCTS.dirent.d_name + ' + i', '0', 'i8') }}};
      pos += {{{ C_STRUCTS.dirent.__size__ }}};
    }
    return pos;
  },
  __syscall221__deps: ['__setErrNo'],
  __syscall221: function(which, varargs) { // fcntl64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd = SYSCALLS.get(), cmd = SYSCALLS.get();
        var arg = 0;

        // only some of the commands have multiple arguments.
        switch (cmd) {
        case {{{ cDefine('F_DUPFD') }}}:
        case {{{ cDefine('F_SETFL') }}}:
        case {{{ cDefine('F_GETLK') }}}:
        case {{{ cDefine('F_GETLK64') }}}:
          arg = SYSCALLS.get();
        }

        var done = function(err) {
          resume(function() {
            return err;
          });
        };
        return BROWSIX.browsix.syscall.syscallAsync(done, 'fcntl64', [fd, cmd, arg]);
      });
#else
      var SYS_FCNTL64 = 221;
      var fd = SYSCALLS.get(), cmd = SYSCALLS.get();
      var arg = 0;

      // only some of the commands have multiple arguments.
      switch (cmd) {
      case {{{ cDefine('F_DUPFD') }}}:
      case {{{ cDefine('F_SETFL') }}}:
      case {{{ cDefine('F_GETLK') }}}:
      case {{{ cDefine('F_GETLK64') }}}:
        arg = SYSCALLS.get();
      }

      return BROWSIX.browsix.syscall.sync(SYS_FCNTL64, fd, cmd, arg);
#endif
    }
#endif
    var stream = SYSCALLS.getStreamFromFD(), cmd = SYSCALLS.get();
    switch (cmd) {
      case {{{ cDefine('F_DUPFD') }}}: {
        var arg = SYSCALLS.get();
        if (arg < 0) {
          return -ERRNO_CODES.EINVAL;
        }
        var newStream;
        newStream = FS.open(stream.path, stream.flags, 0, arg);
        return newStream.fd;
      }
      case {{{ cDefine('F_GETFD') }}}:
      case {{{ cDefine('F_SETFD') }}}:
        return 0;  // FD_CLOEXEC makes no sense for a single process.
      case {{{ cDefine('F_GETFL') }}}:
        return stream.flags;
      case {{{ cDefine('F_SETFL') }}}: {
        var arg = SYSCALLS.get();
        stream.flags |= arg;
        return 0;
      }
      case {{{ cDefine('F_GETLK') }}}:
      case {{{ cDefine('F_GETLK64') }}}: {
        var arg = SYSCALLS.get();
        var offset = {{{ C_STRUCTS.flock.l_type }}};
        // We're always unlocked.
        {{{ makeSetValue('arg', 'offset', cDefine('F_UNLCK'), 'i16') }}};
        return 0;
      }
      case {{{ cDefine('F_SETLK') }}}:
      case {{{ cDefine('F_SETLKW') }}}:
      case {{{ cDefine('F_SETLK64') }}}:
      case {{{ cDefine('F_SETLKW64') }}}:
        return 0; // Pretend that the locking is successful.
      case {{{ cDefine('F_GETOWN_EX') }}}:
      case {{{ cDefine('F_SETOWN') }}}:
        return -ERRNO_CODES.EINVAL; // These are for sockets. We don't have them fully implemented yet.
      case {{{ cDefine('F_GETOWN') }}}:
        // musl trusts getown return values, due to a bug where they must be, as they overlap with errors. just return -1 here, so fnctl() returns that, and we set errno ourselves.
        ___setErrNo(ERRNO_CODES.EINVAL);
        return -1;
      default: {
#if SYSCALL_DEBUG
        Module.printErr('warning: fctl64 unrecognized command ' + cmd);
#endif
        return -ERRNO_CODES.EINVAL;
      }
    }
  },
  __syscall265: function(which, varargs) { // clock_nanosleep
#if SYSCALL_DEBUG
    Module.printErr('warning: ignoring SYS_clock_nanosleep');
#endif
    return 0;
  },
  __syscall268: function(which, varargs) { // statfs64
    var path = SYSCALLS.getStr(), size = SYSCALLS.get(), buf = SYSCALLS.get();
    assert(size === {{{ C_STRUCTS.statfs.__size__ }}});
    // NOTE: None of the constants here are true. We're just returning safe and
    //       sane values.
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_bsize, '4096', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_frsize, '4096', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_blocks, '1000000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_bfree, '500000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_bavail, '500000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_files, 'FS.nextInode', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_ffree, '1000000', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_fsid, '42', 'i32') }}};
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_flags, '2', 'i32') }}};  // ST_NOSUID
    {{{ makeSetValue('buf', C_STRUCTS.statfs.f_namelen, '255', 'i32') }}};
    return 0;
  },
  __syscall269: function(which, varargs) { // fstatfs64
    var stream = SYSCALLS.getStreamFromFD(), size = SYSCALLS.get(), buf = SYSCALLS.get();
    return ___syscall([268, 0, size, buf], 0);
  },
  __syscall272: function(which, varargs) { // fadvise64_64
    return 0; // your advice is important to us (but we can't use it)
  },
  __syscall295: function(which, varargs) { // openat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: openat');
      abort('unsupported syscall openat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), flags = SYSCALLS.get(), mode = SYSCALLS.get();
    path = SYSCALLS.calculateAt(dirfd, path);
    return FS.open(path, flags, mode).fd;
  },
  __syscall296: function(which, varargs) { // mkdirat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: mkdirat');
      abort('unsupported syscall mkdirat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), mode = SYSCALLS.get();
    path = SYSCALLS.calculateAt(dirfd, path);
    return SYSCALLS.doMkdir(path, mode);
  },
  __syscall297: function(which, varargs) { // mknodat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: mknodat');
      abort('unsupported syscall mknodat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), mode = SYSCALLS.get(), dev = SYSCALLS.get();
    path = SYSCALLS.calculateAt(dirfd, path);
    return SYSCALLS.doMknod(path, mode, dev);
  },
  __syscall298: function(which, varargs) { // fchownat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: fchownat');
      abort('unsupported syscall fchownat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), owner = SYSCALLS.get(), group = SYSCALLS.get(), flags = SYSCALLS.get();
    assert(flags === 0);
    path = SYSCALLS.calculateAt(dirfd, path);
    FS.chown(path, owner, group);
    return 0;
  },
  __syscall299: function(which, varargs) { // futimesat
    abort('futimesat is obsolete');
  },
  __syscall300: function(which, varargs) { // fstatat64
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      var dirfd = SYSCALLS.get(), path = SYSCALLS.get(), buf = SYSCALLS.get(), flags = SYSCALLS.get();
      return -ERRNO_CODES.EIO;
    }
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), buf = SYSCALLS.get(), flags = SYSCALLS.get();
    var nofollow = flags & {{{ cDefine('AT_SYMLINK_NOFOLLOW') }}};
    flags = flags & (~{{{ cDefine('AT_SYMLINK_NOFOLLOW') }}});
    assert(!flags, flags);
    path = SYSCALLS.calculateAt(dirfd, path);
    return SYSCALLS.doStat(nofollow ? FS.lstat : FS.stat, path, buf);
  },
  __syscall301: function(which, varargs) { // unlinkat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: unlinkat');
      abort('unsupported syscall unlinkat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), flags = SYSCALLS.get();
    assert(flags === 0);
    path = SYSCALLS.calculateAt(dirfd, path);
    FS.unlink(path);
    return 0;
  },
  __syscall302: function(which, varargs) { // renameat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: renameat');
      abort('unsupported syscall renameat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var olddirfd = SYSCALLS.get(), oldpath = SYSCALLS.getStr(), newdirfd = SYSCALLS.get(), newpath = SYSCALLS.getStr();
    oldpath = SYSCALLS.calculateAt(olddirfd, oldpath);
    newpath = SYSCALLS.calculateAt(newdirfd, newpath);
    FS.rename(oldpath, newpath);
    return 0;
  },
  __syscall303: function(which, varargs) { // linkat
    return -ERRNO_CODES.EMLINK; // no hardlinks for us
  },
  __syscall304: function(which, varargs) { // symlinkat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: symlinkat');
      abort('unsupported syscall symlinkat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var target = SYSCALLS.get(), newdirfd = SYSCALLS.get(), linkpath = SYSCALLS.get();
    linkpath = SYSCALLS.calculateAt(newdirfd, linkpath);
    FS.symlink(target, linkpath);
    return 0;
  },
  __syscall305: function(which, varargs) { // readlinkat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: readlinkat');
      abort('unsupported syscall readlinkat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), buf = SYSCALLS.get(), bufsize = SYSCALLS.get();
    path = SYSCALLS.calculateAt(dirfd, path);
    return SYSCALLS.doReadlink(path, buf, bufsize);
  },
  __syscall306: function(which, varargs) { // fchmodat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: fchmodat');
      abort('unsupported syscall fchmodat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), mode = SYSCALLS.get(), flags = SYSCALLS.get();
    assert(flags === 0);
    path = SYSCALLS.calculateAt(dirfd, path);
    FS.chmod(path, mode);
    return 0;
  },
  __syscall307: function(which, varargs) { // faccessat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: faccessat');
      abort('unsupported syscall faccessat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), amode = SYSCALLS.get(), flags = SYSCALLS.get();
    assert(flags === 0);
    path = SYSCALLS.calculateAt(dirfd, path);
    return SYSCALLS.doAccess(path, amode);
  },
  __syscall308: function(which, varargs) { // pselect
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: pselect');
      abort('unsupported syscall pselect');
    }
#endif
    return -ERRNO_CODES.ENOSYS; // unsupported feature
  },
  __syscall320: function(which, varargs) { // utimensat
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: utimensat');
      abort('unsupported syscall utimensat');
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var dirfd = SYSCALLS.get(), path = SYSCALLS.getStr(), times = SYSCALLS.get(), flags = SYSCALLS.get();
    assert(flags === 0);
    path = SYSCALLS.calculateAt(dirfd, path);
    var seconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_sec, 'i32') }}};
    var nanoseconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_nsec, 'i32') }}};
    var atime = (seconds*1000) + (nanoseconds/(1000*1000));
    times += {{{ C_STRUCTS.timespec.__size__ }}};
    seconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_sec, 'i32') }}};
    nanoseconds = {{{ makeGetValue('times', C_STRUCTS.timespec.tv_nsec, 'i32') }}};
    var mtime = (seconds*1000) + (nanoseconds/(1000*1000));
    FS.utime(path, atime, mtime);
    return 0;  
  },
  __syscall324: function(which, varargs) { // fallocate
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
      console.log('TODO: fallocate');
      abort('unsupported syscall fallocate');
    }
#endif
    var stream = SYSCALLS.getStreamFromFD(), mode = SYSCALLS.get(), offset = SYSCALLS.get64(), len = SYSCALLS.get64();
    assert(mode === 0);
    FS.allocate(stream, offset, len);
    return 0;
  },
  __syscall330: function(which, varargs) { // dup3
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var fd1 = SYSCALLS.get(), fd2 = SYSCALLS.get(), flags = SYSCALLS.get();

        var done = function(result) {
          resume(function() {
            return result|0;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'dup3', [fd1, fd2, flags]);
      });
#else
      var SYS_DUP3 = 330;
      var fd1 = SYSCALLS.get(), fd2 = SYSCALLS.get(), flags = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_DUP3, fd1, fd2, flags);
#endif
    }
#endif
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var old = SYSCALLS.getStreamFromFD(), suggestFD = SYSCALLS.get(), flags = SYSCALLS.get();
    assert(!flags);
    if (old.fd === suggestFD) return -ERRNO_CODES.EINVAL;
    return SYSCALLS.doDup(old.path, old.flags, suggestFD);
  },
  __syscall331: function(which, varargs) { // pipe2
#if BROWSIX
    if (ENVIRONMENT_IS_BROWSIX) {
#if EMTERPRETIFY_ASYNC
      return EmterpreterAsync.handle(function(resume) {
        var pipefd = SYSCALLS.get(), flags = SYSCALLS.get();
        var done = function(err, fd1, fd2) {
          if (!err) {
            HEAP32[(pipefd>>2)] = fd1;
            HEAP32[(pipefd>>2)+1] = fd2;
          }
          resume(function() {
            return err || 0;
          });
        };
        BROWSIX.browsix.syscall.syscallAsync(done, 'pipe2', [flags]);
      });
#else
      var SYS_PIPE2 = 41;
      var pipefd = SYSCALLS.get(), flags = SYSCALLS.get();
      return BROWSIX.browsix.syscall.sync(SYS_PIPE2, pipefd, flags);
#endif
    }
#endif
    return -ERRNO_CODES.ENOSYS; // unsupported feature
  },
  __syscall333: function(which, varargs) { // preadv
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var stream = SYSCALLS.getStreamFromFD(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get(), offset = SYSCALLS.get();
    return SYSCALLS.doReadv(stream, iov, iovcnt, offset);
  },
  __syscall334: function(which, varargs) { // pwritev
#if SYSCALL_DEBUG
    Module.printErr('warning: untested syscall');
#endif
    var stream = SYSCALLS.getStreamFromFD(), iov = SYSCALLS.get(), iovcnt = SYSCALLS.get(), offset = SYSCALLS.get();
    return SYSCALLS.doWritev(stream, iov, iovcnt, offset);
  },
  __syscall340: function(which, varargs) { // prlimit64
    var pid = SYSCALLS.get(), resource = SYSCALLS.get(), new_limit = SYSCALLS.get(), old_limit = SYSCALLS.get();
    if (old_limit) { // just report no limits
      {{{ makeSetValue('old_limit', C_STRUCTS.rlimit.rlim_cur, '-1', 'i32') }}};  // RLIM_INFINITY
      {{{ makeSetValue('old_limit', C_STRUCTS.rlimit.rlim_cur + 4, '-1', 'i32') }}};  // RLIM_INFINITY
      {{{ makeSetValue('old_limit', C_STRUCTS.rlimit.rlim_max, '-1', 'i32') }}};  // RLIM_INFINITY
      {{{ makeSetValue('old_limit', C_STRUCTS.rlimit.rlim_max + 4, '-1', 'i32') }}};  // RLIM_INFINITY
    }
    return 0;
  },
*/
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
