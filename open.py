
import frida, sys
 
jsCode = """
Java.perform(function(){
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';   //需要hook的so名
    var n_addr_func_offset = 0xE544E4;     //需要hook的函数的偏移.0xE544E4.set.0xE5453C.get
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var arg0 = new NativePointer(0x6d71181410);
    var nativePointer = new NativePointer(n_addr_func);
    send("native: " + nativePointer);
    //send("hexdump:"+hexdump(0x78183d0e60));

    var OnCollect = new NativeFunction(nativePointer,'void',["pointer","double"]);
    //send("ok");

    Interceptor.attach(OnCollect, {
        onEnter: function(args){
            send("fun2  start....");
            send(args[0])
        },
        onLeave: function(retval){
            send("retval:"+retval);
            //send("retval:"+retval.toInt32());
            //send(Memory.readDouble(retval));
            //retval.replace(1);
            
            send("fun2  over.....")
        }
    });
    OnCollect(arg0,20);
    



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