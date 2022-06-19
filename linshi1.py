
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    send("so基址："+n_addr_so);
    var getval_offset = 0xE5453C;     //需要hook的函数的偏移.0xE544E4.set.0xE5453C.get
    var setval_offset = 0xE544E4; 
    var getval_func = parseInt(n_addr_so, 16) + getval_offset;
    var setval_func = parseInt(n_addr_so, 16) + setval_offset;
    var getval_Pointer = new NativePointer(getval_func);
    var setval_Pointer = new NativePointer(setval_func);
    var set_val = new NativeFunction(setval_Pointer,'void',["pointer","double"]);
    var get_val = new NativeFunction(getval_Pointer,'int',["pointer"]);
    /*
    var addr=new NativePointer(0x6dbfc5a540);
    var Btd6Player_addr=addr.add(0x39);
    console.log(hexdump(Btd6Player_addr));*/
    var col=Memory.alloc(8);

    

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