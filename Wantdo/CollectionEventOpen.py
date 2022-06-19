
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0x158C17C;         //需要hook的函数的偏移
    /*
    RVA: 0x1587B54 Offset: 0x1587B54 VA: 0x1587B54
	public int get_AmountCollected() { }
    */
    var struct_addr;
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    /*
    // RVA: 0x1588F4C Offset: 0x1588F4C VA: 0x1588F4C
	public List<LootSet> GenerateLootSets() { }
    */
    var GenerateLootSets_offset = 0x158C17C;     //需要hook的函数的偏移
    var GenerateLootSets_func = parseInt(n_addr_so, 16) + GenerateLootSets_offset;
    var GenerateLootSets_Pointer = new NativePointer(GenerateLootSets_func);
    var GenerateLootSets = new NativeFunction(GenerateLootSets_Pointer,'pointer',["pointer"]);
    var struct_addr = new NativePointer(0x779af631b0)
    //GenerateLootSets(struct_addr)
    Interceptor.attach(nativePointer,{
        onEnter: function(args){
            send("start....");
            send("struct_addr: "+args[0]);
            struct_addr=args[0];
            },
         onLeave: function(retval){
            //send("AmountCollected:"+retval.toInt32());
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

str_host="192.168.204.205:1234"
manager=frida.get_device_manager()
remote_device=manager.add_remote_device(str_host)
process= remote_device.attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()