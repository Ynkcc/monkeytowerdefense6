
import frida, sys
 
jsCode = """
Java.perform(function(){
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset = 0x1587B54;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("native: " + nativePointer);
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            send("start....");
            send(args[0]);
            send(args[1]);
            send(args[2]);
            send(args[3]);
            send(args[4]);
            send(args[5]);
            send(args[6]);
            send(args[7]);
            send(args[8]);
            send(args[9]);
            send(args[10]);
            send(args[11]);
            send(args[12]);
            send(args[13]);
            send(args[14]);
            send(args[15]);
            send(args[16]);
            send(args[17]);
            send(args[18]);
            send("尝试read float");
            send(args[13].readS32());
            send(args[14].readS32());
            send(args[15].readS32());
            //send('arg1: '+args[2].readCString());
            //send('arg2: '+args[3]);

            
        },
        onLeave: function(retval){
            send("retval:"+retval);
            //retval.replace(1);
            //send("retval:"+ptr(Java.vm.tryGetEnv().getStringUtfChars(retval)).readCString());
            send("over.....")
        }
    });
});
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)
 
process = frida.get_remote_device().attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()