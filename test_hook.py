"""Minimal Frida hook test - ONE script"""
import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"
os.system("taskkill /f /im iCarsoft_MSDIAG_PCClientKits.exe >nul 2>&1")
time.sleep(1)

pid = frida.spawn(UPDATER)
s = frida.attach(pid)

HOOK = """
var k32 = Process.findModuleByName('kernel32.dll');
console.log('K32=' + k32.name);
var wf = k32.findExportByName('WriteFile');
console.log('WF=' + wf);

Interceptor.attach(wf, {
    onEnter: function(a) {
        var sz = a[2].toInt32();
        if (sz >= 64) console.log('W:' + sz);
    }
});
console.log('OK');
"""

sc = s.create_script(HOOK)
sc.on('message', lambda m, d: print(f"MSG: {m}"))
sc.load()
frida.resume(pid)
print("Resumed. Do something in updater...")
time.sleep(60)
print("Done.")
