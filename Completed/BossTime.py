
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0xF68A6C;         //需要hook的函数的偏移
    /*
    RVA: 0xF68A6C Offset: 0xF68A6C VA: 0xF68A6C
	public TimeSpan GetPenaltyTime() { }
    */
    var struct_addr;
    var bossTimes=0x38;   //private KonFuze[] bossTimes; // 0x38
    var penaltyTime=0x40; //private KonFuze penaltyTime; // 0x40
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var bossTimes_addr;
    var penaltyTime_addr;
    send("so基址："+n_addr_so);
    send("native: " + nativePointer);
    
    
    var getval_offset = 0xE5453C;     //需要hook的函数的偏移.0xE544E4.set.0xE5453C.get
    var setval_offset = 0xE544E4; 
    var getval_func = parseInt(n_addr_so, 16) + getval_offset;
    var setval_func = parseInt(n_addr_so, 16) + setval_offset;
    var getval_Pointer = new NativePointer(getval_func);
    var setval_Pointer = new NativePointer(setval_func);
    var set_val = new NativeFunction(setval_Pointer,'void',["pointer","double"]);
    var get_val = new NativeFunction(getval_Pointer,'int',["pointer"]);

    Interceptor.attach(nativePointer, {
        onEnter: function(args){
            send("start....");
            send("struct_addr "+args[0]);
            penaltyTime_addr = args[0].add(penaltyTime);
            var ptFuze=penaltyTime_addr.readPointer();
            send("penaltyTime: "+get_val(ptFuze))
            set_val(ptFuze,204)
            bossTimes_addr=args[0].add(bossTimes);
            var btFuzeArray=bossTimes_addr.readPointer();
            btFuzeArray=btFuzeArray.add(0x20);
            for(var j=0;j<5;j++){
                var btFuze=btFuzeArray.readPointer();
                send("bossTime: "+get_val(btFuze))
                set_val(btFuze,2200)
                btFuzeArray=btFuzeArray.add(0x8);
            }
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