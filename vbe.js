var loadedModules = {}
var resolvedAddresses = {}

function resolveName(dllName, name) {
  var moduleName = dllName.split('.')[0]
  var functionName = moduleName + "!" + name

  if (functionName in resolvedAddresses) {
    return resolvedAddresses[functionName]
  }

  log("resolveName " + functionName);
  log("Module.findExportByName " + dllName + " " + name);
  var addr = Module.findExportByName(dllName, name)

  if (!addr || addr.isNull()) {
    if (!(dllName in loadedModules)) {
      log(" DebugSymbol.loadModule " + dllName);

      try {
        DebugSymbol.load(dllName)
      } catch (err) {
        return 0;
      }

      log(" DebugSymbol.load finished");
      loadedModules[dllName] = 1
    }

    try {
      log(" DebugSymbol.getFunctionByName: " + functionName);
      addr = DebugSymbol.getFunctionByName(moduleName + '!' + name)
      log(" DebugSymbol.getFunctionByName: addr = " + addr);
    } catch (err) {
      log(" DebugSymbol.getFunctionByName: Exception")
    }
  }

  resolvedAddresses[functionName] = addr
  return addr
}

function loadModuleForAddress(address) {
  var modules = Process.enumerateModules()

  var i
  for (i = 0; i < modules.length; i++) {
    if (address >= modules[i].base && address <= modules[i].base.add(modules[i].size)) {
      log(" " + modules[i].name + ": " + modules[i].base + " " + modules[i].size + " " + modules[i].path)

      var modName = modules[i].path
      if (!(modName in loadedModules)) {
        log("  DebugSymbol.loadModule " + modName);

        try {
          DebugSymbol.load(modName)
        } catch (err) {
          return 0;
        }

        loadedModules[modName] = 1
      }
      break
    }
  }
}

var hookedFunctions = {}
var addressToFunctions = {}
var blackListedFunctions = {
  'I_RpcClearMutex': 1
}

function hookFunction(dllName, funcName, callback) {
  if (funcName in blackListedFunctions) {
    return
  }
  var symbolName = dllName + "!" + funcName
  if (symbolName in hookedFunctions) {
    return
  }
  hookedFunctions[symbolName] = 1

  var addr = resolveName(dllName, funcName)
  if (!addr || addr.isNull()) {
    return
  }

  if (addr in hookedFunctions) {
    return
  }
  hookedFunctions[addr] = 1

  addressToFunctions[addr] = symbolName
  log('Interceptor.attach: ' + symbolName + '@' + addr);
  Interceptor.attach(addr, callback)
}

function hookPointers(address, count) {
  if (address.isNull())
    return

  var currentAddress = address
  for (var i = 0; i < count; i++) {
    var readAddress = ptr(currentAddress).readPointer();
    readAddress = ptr(readAddress)
    var symbolInformation = DebugSymbol.fromAddress(readAddress)

    var name = readAddress
    if (symbolInformation && symbolInformation.name) {
      name = symbolInformation.name
    }

    log('Hooking ' + readAddress + ": " + name)

    try {
      Interceptor.attach(readAddress, {
        onEnter: function (args) {
          log('[+] ' + name)
        }
      })
    } catch (err) {}
    currentAddress = currentAddress.add(4)
  }
}

function hookFunctionNames(moduleName, funcNames) {
  for (var i = 0; i < funcNames.length; i++) {
    var funcName = funcNames[i]

    try {
      hookFunction(moduleName, funcName, {
        onEnter: function (args) {
          var name = ''
          if (this.context.pc in addressToFunctions) {
            name = addressToFunctions[this.context.pc]
          }
          log("[+] " + name + " (" + this.context.pc + ")")
        }
      })
    } catch (err) {
      log("Failed to hook " + funcName)
    }
  }
}

function BytesToCLSID(address) {
  if (address.isNull())
    return

  var data = new Uint8Array(ptr(address).readByteArray(0x10))
  var clsid = "{" + getHexString(data[3]) + getHexString(data[2]) + getHexString(data[1]) + getHexString(data[0])
  clsid += '-' + getHexString(data[5]) + getHexString(data[4])
  clsid += '-' + getHexString(data[7]) + getHexString(data[6])
  clsid += '-' + getHexString(data[8]) + getHexString(data[9])
  clsid += '-' + getHexString(data[10]) + getHexString(data[11]) + getHexString(data[12]) + getHexString(data[13]) + getHexString(data[14]) + getHexString(data[15])
  clsid += '}'

  return clsid
}

function log(message) {
  console.log(message)
}

function dumpAddress(address) {
  log('[+] address: ' + address);

  if (address.isNull())
    return
  var data = ptr(address).readByteArray(50);
  log(hexdump(data, {
    offset: 0,
    length: 50,
    header: true,
    ansi: false
  }));
}

function dumpBytes(address, length) {
  if (address.isNull())
    return
  var data = ptr(address).readByteArray(length);
  log(hexdump(data, {
    offset: 0,
    length: length,
    header: true,
    ansi: false
  }));
}

function dumpSymbols(address, count) {
  if (address.isNull())
    return

  var currentAddress = address
  for (var i = 0; i < count; i++) {
    var readAddress = ptr(currentAddress).readPointer();
    readAddress = ptr(readAddress)
    var symbolInformation = DebugSymbol.fromAddress(readAddress)

    if (symbolInformation && symbolInformation.name) {
      log(currentAddress + ":\t" + readAddress + " " + symbolInformation.name)
    } else {
      log(currentAddress + ":\t" + readAddress)
    }
    currentAddress = currentAddress.add(4)
  }
}

function dumpBSTR(address) {
  log('[+] address: ' + address);

  if (address.isNull())
    return

  var length = ptr(address - 4).readULong(4);
  log("length: " + length)
  var data = ptr(address).readByteArray(length);
  log(hexdump(data, {
    offset: 0,
    length: length,
    header: true,
    ansi: false
  }));
}

function getString(address) {
  if (address.isNull())
    return

  var dataString = ''

  var offset = 0
  var stringEnded = false
  while (!stringEnded) {
    var data = new Uint8Array(ptr(address.add(offset)).readByteArray(10));

    if (data.length <= 0) {
      break
    }

    var i;
    for (i = 0; i < data.length; i++) {
      if (data[i] == 0x0) {
        stringEnded = true
        break
      }
      dataString += String.fromCharCode(data[i])
    }
    offset += data.length
  }

  log("dataString: " + dataString)
  return dataString;
}

function dumpWSTR(address) {
  if (address.isNull())
    return

  var dataString = ''

  var offset = 0
  var stringEnded = false
  while (!stringEnded) {
    var data = new Uint8Array(ptr(address.add(offset)).readByteArray(20));

    if (data.length <= 0) {
      break
    }

    var i;
    for (i = 0; i < data.length; i += 2) {
      if (data[i] == 0x0 && data[i + 1] == 0x0) {
        stringEnded = true
        break
      }
      dataString += String.fromCharCode(data[i])
    }
    offset += data.length
  }

  log("dataString: " + dataString)
  return dataString;
}

function hookRtcShell(moduleName) {
  hookFunction(moduleName, "rtcShell", {
    onEnter: function (args) {
      log("[+] rtcShell")
      var variantArg = ptr(args[0])
      dumpAddress(variantArg);
      var bstrPtr = ptr(variantArg.add(8).readULong())
      dumpBSTR(bstrPtr);
    }
  })
}

function hookVBAStrCat(moduleName) {
  hookFunction(moduleName, "__vbaStrCat", {
    onEnter: function (args) {
      log("[+] __vbaStrCat")
      // log('[+] ' + name);
      // dumpBSTR(args[0]);
      // dumpBSTR(args[1]);
    },
    onLeave: function (retval) {
      dumpBSTR(retval);
    }
  })
}

function hookVBAStrComp(moduleName) {
  hookFunction(moduleName, "__vbaStrComp", {
    onEnter: function (args) {
      log('[+] __vbaStrComp');
      log(ptr(args[1]).readUtf16String())
      log(ptr(args[2]).readUtf16String())
    }
  })
}

function hookRtcCreateObject(moduleName) {
  hookFunction(moduleName, "rtcCreateObject", {
    onEnter: function (args) {
      log('[+] rtcCreateObject');
      dumpAddress(args[0]);
      dumpBSTR(args[0]);
      log(ptr(args[0]).readUtf16String())
    },
    onLeave: function (retval) {
      dumpAddress(retval);
    }
  })
}

function hookRtcCreateObject2(moduleName) {
  hookFunction(moduleName, "rtcCreateObject2", {
    onEnter: function (args) {
      log('[+] rtcCreateObject2');
      dumpAddress(args[0]);
      dumpBSTR(args[1]);
      log(ptr(args[2]).readUtf16String())
    },
    onLeave: function (retval) {
      dumpAddress(retval);
    }
  })
}

//  int __stdcall CVbeProcs::CallMacro(CVbeProcs *this, const wchar_t *)
function hookCVbeProcsCallMacro(moduleName) {
  hookFunction(moduleName, "CVbeProcs::CallMacro", {
    onEnter: function (args) {
      log('[+] CVbeProcs::CallMacro');
      dumpAddress(args[0]);
      dumpWSTR(args[1]);
    },
    onLeave: function (retval) {
      dumpAddress(retval);
    }
  })
}

function hookDispCall(moduleName) {
  hookFunction(moduleName, "DispCallFunc", {
    onEnter: function (args) {
      log("[+] DispCallFunc")
      var pvInstance = args[0]
      var oVft = args[1]
      var instance = ptr(ptr(pvInstance).readULong());

      log(' instance:' + instance);
      log(' oVft:' + oVft);
      var vftbPtr = instance.add(oVft)
      log(' vftbPtr:' + vftbPtr);
      var functionAddress = ptr(ptr(vftbPtr).readULong())

      loadModuleForAddress(functionAddress)
      var functionName = DebugSymbol.fromAddress(functionAddress)

      if (functionName) {
        log(' functionName:' + functionName);
      }

      dumpAddress(functionAddress);

      var currentAddress = functionAddress
      for (var i = 0; i < 10; i++) {
        try {
          var instruction = Instruction.parse(currentAddress)
          log(instruction.address + ': ' + instruction.mnemonic + ' ' + instruction.opStr)
          currentAddress = instruction.next
        } catch (err) {
          break
        }
      }
    }
  })
}

hookRtcShell('vbe7')
hookVBAStrCat('vbe7')
hookVBAStrComp('vbe7')
hookRtcCreateObject('vbe7')
hookRtcCreateObject2('vbe7')
hookCVbeProcsCallMacro('vbe7')
hookDispCall('oleaut32')