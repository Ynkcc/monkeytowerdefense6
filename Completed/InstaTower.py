
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0xE99FD4;         //需要hook的函数的偏移
    /*
    RVA: 0xE99FD4 Offset: 0xE99FD4 VA: 0xE99FD4
	public int get_Quantity() { }
    */
    var struct_addr;
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    /*
    // RVA: 0xE9B65C Offset: 0xE9B65C VA: 0xE9B65C
	public void set_Quantity(int value) { }
    
    // RVA: 0xE9B74C Offset: 0xE9B74C VA: 0xE9B74C
	public int GetTier() { }
    */
    var GetTier_offset = 0xE9B74C;     //需要hook的函数的偏移
    var set_Quantity_offset = 0xE9B65C; 
    var getval_func = parseInt(n_addr_so, 16) + GetTier_offset;
    var setval_func = parseInt(n_addr_so, 16) + set_Quantity_offset;
    var getval_Pointer = new NativePointer(getval_func);
    var setval_Pointer = new NativePointer(setval_func);
    var set_Quantity = new NativeFunction(setval_Pointer,'void',["pointer","int"]);
    var GetTier = new NativeFunction(getval_Pointer,'int',["pointer"]);

    Interceptor.attach(nativePointer,{
        onEnter: function(args){
            send("start....");
            send("struct_addr: "+args[0]);
            struct_addr=args[0];
            },
         onLeave: function(retval){
            send("quantity:"+retval.toInt32());
            send("GetTier: "+GetTier(struct_addr));
            set_Quantity(struct_addr,10);
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