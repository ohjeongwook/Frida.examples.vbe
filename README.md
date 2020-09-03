# Frida.examples.vbe

Frida example to trace VBA CreateObject calls and some string deobfuscations calls. You need latest Frida 12.9.8 for improved symbol lookup features I added recently.

It uses improved DebugSymbol.getFunctionByName to perform symbol lookup. The following Javascript code shows a good example of using Module.findExportByName and DebugSymbol.getFunctionByName with name and module caches to expedite symbol lookup in general.

```
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
```

## Publications

* [Using Frida For Windows Reverse Engineering](https://darungrim.com/research/2020-06-17-using-frida-for-windows-reverse-engineering.html)
