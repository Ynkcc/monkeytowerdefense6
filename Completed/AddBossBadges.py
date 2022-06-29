import frida, sys

jsCode = """
Java.perform(function(){
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0xE14310;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("so基址："+n_addr_so);
    send("函数地址: " + nativePointer);

    var Btd6Player_addr=null;
    var bossType=2;//Bloonarius = 0;Lych = 1;Vortex = 2;
    var isElite=1; //0 or 1
    var amount=1;

    var addval_offset = 0xE1400C; 
    var addval_func = parseInt(n_addr_so, 16) + addval_offset;
    var addval_Pointer = new NativePointer(addval_func);
    var set_val = new NativeFunction(addval_Pointer,'void',["pointer","uint","bool","uint"]);

    Interceptor.attach(nativePointer, {
        onEnter: function(args){
        if(Btd6Player_addr==null){
        send("得到Btd6Player_addr。。。");
            Btd6Player_addr=args[0];
            send("Btd6Player_addr "+args[0]);
            set_val(Btd6Player_addr,bossType,isElite,amount);
            }   }
    });
    
    
    

    

});
"""
 
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