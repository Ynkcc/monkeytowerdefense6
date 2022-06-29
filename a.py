
import frida, sys
 
jsCode = """
Java.perform(function(){
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset = 0xE544A0;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("native: " + nativePointer);
    var docp;
    var tmp;
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            send("start....");
            send("args[0]:"+args[0]);
            send("args[1]:"+args[1]);
            send("args[2]:"+args[2]);
            //send(args[1].readU32())
            //docp=args[0].add(0x28);
        },
        onLeave: function(retval){
            //send("read "+docp.readDouble())
            send("retval:"+retval);
            //tmp=Memory.alloc(8);
            //tmp.writePointer(retval)
            //send("retval 2:"+tmp.readDouble());


        }
    });
});
""";
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)

str_host="192.168.104.205:1234"
manager=frida.get_device_manager()
remote_device=manager.add_remote_device(str_host)
process= remote_device.attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()