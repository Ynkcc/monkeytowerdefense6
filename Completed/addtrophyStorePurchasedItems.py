import frida, sys

jsCode = """
Java.perform(function () {
    var str_name_so = 'libil2cpp.so';    //需要hook的so名
    var n_addr_func_offset = 0xE14310;         //需要hook的函数的偏移
    var n_addr_so = Module.findBaseAddress(str_name_so); //加载到内存后 函数地址 = so地址 + 函数偏移
    var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;
    var nativePointer = new NativePointer(n_addr_func);
    send("so基址：" + n_addr_so);
    send("函数地址: " + nativePointer);

    var Btd6Player_addr = null;

    /*
    RVA: 0xE1802C Offset: 0xE1802C VA: 0xE1802C
    public void AddTrophyStoreItem(string trophyStoreId) { }
    */
    var addval_offset = 0xE1802C;
    var addval_func = parseInt(n_addr_so, 16) + addval_offset;
    var addval_Pointer = new NativePointer(addval_func);
    var addval = new NativeFunction(addval_Pointer, 'void', ["pointer", "pointer"]);

    var fun_offset = 0x2476514;
    var fun_func = parseInt(n_addr_so, 16) + fun_offset;
    var fun_Pointer = new NativePointer(fun_func);
    var fun = new NativeFunction(fun_Pointer, 'pointer', ["int"]);

    Interceptor.attach(nativePointer, {
        onEnter: function (args) {
            if (Btd6Player_addr == null) {
                send("得到Btd6Player_addr。。。");
                Btd6Player_addr = args[0];
                send("Btd6Player_addr " + args[0]);

                var idlist = ["BloonsAllBloonsBunnyEars", "BloonsAllBloonsDaisyChain", "BloonsAllBloonsDecalAxe", "BloonsAllBloonsElfHat", "BloonsAllBloonsPopsBones", "BloonsAllBloonsPopsPewpew", "BloonsAllBloonsRudolphNose", "BloonsAllBloonsSantaHats", "BloonsAllBloonsVampireCapes", "BloonsBFBSkinChocolate", "BloonsDDTSkinSleigh", "BloonsMOABSkinChocolate", "BloonsZOMGSkinJackOLantern", "CoopEmoteAnimationObynPeace", "GameUIMusicTrackMusicHaunted", "GameUIPowerSkinBaubleMine", "GameUIPowerSkinCoffinDrop", "GameUIPowerSkinEnergisingTotemChristmasTree", "GameUIPowerSkinHalloweenFarmer", "GameUIPowerSkinMonkeyBoostFireworks", "GameUIPowerSkinRetroTechbot", "GameUIProfileAvatar25", "GameUIProfileAvatar26", "GameUIProfileAvatar29", "GameUIProfileAvatar30", "GameUIProfileAvatar33", "GameUIProfileAvatar43", "GameUIProfileAvatar48", "GameUIProfileAvatar55", "GameUIProfileAvatar56", "GameUIProfileBanner12", "HeroesObynPetBunny", "HeroesPatPetPenguin", "TowerEffectAllMonkeysPlacementUpgradesFireworks", "TowerEffectAllMonkeysPlacementUpgradesPresents", "TowerPetIceMonkeySnowman", "TowerPetMonkeyVillageElf", "TowerProjectileBananaFarmCandyCorn", "TowerProjectileBombshooterPumpkin", "TowerProjectileBoomerangCandyCane", "TowerProjectileDartlingEasterEggs", "TowerProjectileEngineerVampireHunter", "TowerProjectileMonkeyAceBones", "TowerProjectileMortarSnow", "TowerProjectileWizardMonkeyFireworks"]
                for (var i = 0; i < idlist.length; i++) {
                    var id = idlist[i];
                    var trophyStoreId = fun(120);
                    var length_offset = trophyStoreId.add(0x10);
                    var string_offset = trophyStoreId.add(0x14)
                    length_offset.writeInt(id.length)
                    string_offset.writeUtf16String(id)
                    addval(Btd6Player_addr, trophyStoreId);
                }


            }
        }
    });

});
"""
 
def message(message, data):
    if message["type"] == 'send':
        print(u"[*] {0}".format(message['payload']))
    else:
        print(message)
 
str_host="192.168.209.205:1234"
manager=frida.get_device_manager()
remote_device=manager.add_remote_device(str_host)
process= remote_device.attach("Bloons TD 6")
script= process.create_script(jsCode)
script.on("message", message)
script.load()
sys.stdin.read()