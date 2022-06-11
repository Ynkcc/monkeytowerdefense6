
import frida, sys
 
jsCode = """
Java.perform(function(){
    
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset =0x1587B54;         //需要hook的函数的偏移
    /*
    RVA: 0x1587B54 Offset: 0x1587B54 VA: 0x1587B54
	public int get_AmountCollected() { }
    */
    var struct_addr;
    var collectionEventProfileData=0x38;   //字段偏移 private CollectionEventDataModel collectionEventProfileData; // 0x38
    var amountCollected=0x18; //public KonFuze amountCollected; // 0x18
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    var collectionEventProfileData_addr;
    var amountCollected_addr;
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
            if(collectionEventProfileData_addr==null){
            send("start....");
            send("struct_addr "+args[0]);
            collectionEventProfileData_addr = args[0].add(collectionEventProfileData);
            var i=collectionEventProfileData_addr.readPointer();//临时变量 i
            amountCollected_addr=i.add(amountCollected);
            var j=amountCollected_addr.readPointer();
            send("trophies: "+get_val(j));
            set_val(j,17000)
            send("trophies: "+get_val(j));
            send("over.....")
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