
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    //var nativePointer = Module.findExportByName("libhello.so", "Java_com_xiaojianbang_app_NativeHelper_add");
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    send("so基址："+n_addr_so);
    
    

    var ctor_offset = 0xE80CAC; 
    var ctor_func = parseInt(n_addr_so, 16) + ctor_offset;
    var ctor_Pointer = new NativePointer(ctor_func);
    var ctor = new NativeFunction(ctor_Pointer,'void',["pointer"]);

    
    var setval_offset = 0xE823F8; 
    var setval_func = parseInt(n_addr_so, 16) + setval_offset;
    var setval_Pointer = new NativePointer(setval_func);
    var set_val = new NativeFunction(setval_Pointer,'void',["pointer"]);

  
  
    var lootset=Memory.alloc(0x1000);
    ctor(lootset);
    set_val(lootset);
    send("over")
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