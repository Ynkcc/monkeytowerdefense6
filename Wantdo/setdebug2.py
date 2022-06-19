import frida, sys

jsCode = """
Java.perform(function(){
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0xCCA4D4;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("so基址："+n_addr_so);
    send("函数地址: " + nativePointer);

    var Btd6Player_addr=null;
    Interceptor.attach(nativePointer, {
        onEnter: function(args){
        if(Btd6Player_addr==null){
        send("得到Btd6Player_addr。。。");
            Btd6Player_addr=args[0];
            send("Btd6Player_addr "+args[0]);
            Btd6Player_addr=Btd6Player_addr.add(0x39);
            console.log(hexdump(Btd6Player_addr));
            Btd6Player_addr.writeByteArray([0x01,0x01]);
            console.log(hexdump(Btd6Player_addr));
            }   }
    });
    
    
    

    

});
"""
 
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