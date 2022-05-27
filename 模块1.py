
import frida, sys
 
jsCode = """




Java.perform(function () {
var NewStringUTFPtr = null;  

//console.log( JSON.stringify(Process.enumerateModules()));
var symbols = Process.findModuleByName("libart.so").enumerateSymbols();
for(var i = 0;i<symbols.length;i++){
    var symbol = symbols[i].name;
    if((symbol.indexOf("CheckJNI")==-1)&&(symbol.indexOf("JNI")>=0)){
        if(symbol.indexOf("NewStringUTF")>=0&&symbol.indexOf("prev_bad_input_time")==-1){  // 以GetStringUTFChars为例
            console.log(symbols[i].name);
            console.log(symbols[i].address);
            NewStringUTFPtr = symbols[i].address;
        }
    }
}
console.log("addr_NewStringUTF:",NewStringUTFPtr);
Interceptor.attach(NewStringUTFPtr, {
    onEnter: function (args) {
        //send(Memory.readUtf8String(args[1]));
        send(Memory.readCString(args[1]));
        var buffer = Memory.readByteArray(args[1],16);
        console.log(hexdump(buffer, {
            offset: 0,
            length: 16,
            header: true,
            ansi: false
        }));

    },
    onLeave: function(retval){
        send("jni返回的：" + retval);
    }
});
})
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)
 
str_host="192.168.31.13:11678"
manager=frida.get_device_manager()
remote_device=manager.add_remote_device(str_host)
process= remote_device.attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()
