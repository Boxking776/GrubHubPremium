

local exploit = (syn and 'Synapse') or (KRNL_LOADED and 'Krnl') or (pebc_execute and 'Protosmasher') or (secure_load and 'Sentinel');
local http_request = (syn and syn.request) or (SENTINEL_V2 and request) or (PROTOSMASHER_LOADED and http_request) or (KRNL_LOADED and request);


local hash; do
    local MOD = 2^32
    local MODM = MOD-1
    local bxor = bit32.bxor;
    local band = bit32.band;
    local bnot = bit32.bnot;
    local rshift1 = bit32.rshift;
    local rshift = bit32.rshift;
    local lshift = bit32.lshift;
    local rrotate = bit32.rrotate;

    local str_gsub = string.gsub;
    local str_fmt = string.format;
    local str_byte = string.byte;
    local str_char = string.char;
    local str_rep = string.rep;

    local k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }
    local function str2hexa(s)
        return (str_gsub(s, ".", function(c) return str_fmt("%02x", str_byte(c)) end))
    end
    local function num2s(l, n)
        local s = ""
        for i = 1, n do
            local rem = l % 256
            s = str_char(rem) .. s
            l = (l - rem) / 256
        end
        return s
    end
    local function s232num(s, i)
        local n = 0
        for i = i, i + 3 do n = n*256 + str_byte(s, i) end
        return n
        end
        local function preproc(msg, len)
        local extra = 64 - ((len + 9) % 64)
        len = num2s(8 * len, 8)
        msg = msg .. "\128" .. str_rep("\0", extra).. len
        assert(#msg % 64 == 0)
        return msg
    end
    local function initH256(H)
        H[1] = 0x6a09e667
        H[2] = 0xbb67ae85
        H[3] = 0x3c6ef372
        H[4] = 0xa54ff53a
        H[5] = 0x510e527f
        H[6] = 0x9b05688c
        H[7] = 0x1f83d9ab
        H[8] = 0x5be0cd19
        return H
    end
    local function digestblock(msg, i, H)
        local w = {}
        for j = 1, 16 do w[j] = s232num(msg, i + (j - 1)*4) end
        for j = 17, 64 do
            local v = w[j - 15]
            local s0 = bit.bxor(rrotate(v, 7), rrotate(v, 18), bit.rshift(v, 3))
            v = w[j - 2]
            w[j] = w[j - 16] + s0 + w[j - 7] + bit.bxor(rrotate(v, 17), rrotate(v, 19), bit.rshift(v, 10))
        end
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for i = 1, 64 do
            local s0 = bit.bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
            local maj = bit.bxor(band(a, b), band(a, c), band(b, c))
            local t2 = s0 + maj
            local s1 = bit.bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
            local ch = bit.bxor(band(e, f), bit.band(bit.bnot(e), g))
            local t1 = h + s1 + ch + k[i] + w[i]
            h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
        end
        H[1] = band(H[1] + a)
        H[2] = band(H[2] + b)
        H[3] = band(H[3] + c)
        H[4] = band(H[4] + d)
        H[5] = band(H[5] + e)
        H[6] = band(H[6] + f)
        H[7] = band(H[7] + g)
        H[8] = band(H[8] + h)
    end
    function hash(msg, t) 
        msg = preproc(msg, #msg)
        local H = initH256({})
        for i = 1, #msg, 64 do digestblock(msg, i, H) end
        return str2hexa(num2s(H[1], 4) .. num2s(H[2], 4) .. num2s(H[3], 4) .. num2s(H[4], 4) .. num2s(H[5], 4) .. num2s(H[6], 4) .. num2s(H[7], 4) .. num2s(H[8], 4))
    end
   function hmac(secret, data)
       return hash(secret .. data .. secret);
   end;
end

local Key = getgenv().Key or "";

function uniformRNG(a, b)
    a1 = 48718057
        a2 = 58305628

    b1 = 108466472
        b2 = 1090878788885

    x1 = a
        x2 = b

    r1 = (x2 * a2)
    r2 = (x1 * a2 + x2 * a1) % b1
    r2 = (r2 * b1 + r2) % b2

    x1 = math.floor(r2 / b1)
    x2 = r2 - x1 * b1

    return math.floor((r2 / b2) * math.pow(10, 12))
end
local function generate_order()
     math.randomseed(tick()/4)
     local options = {}
     local new_options = {}
     while #options ~= 3 do
         local num = math.random(1,3) 
         if not new_options[num] then
             table.insert(options,num)
             new_options[num] = true
         end
     end
     return options
end
local function eq(v1,v2)
    math.randomseed(tick()/4)
    local charset = "ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz1234567890"
    if type(v1) == "string" and type(v2) == "string" then
        local length1,length2,chars_1,chars_2 = #v1,#v2,{},{}
        v1:gsub(".",function(s)chars_1[#chars_1+1]=s end)
        v2:gsub(".",function(s)chars_2[#chars_2+1]=s end)
        if (length1~=length2) then
            return false
        end
        local start = math.random(1,length1)
        local bool = true
        for i,v in pairs(generate_order()) do
            if v == 1 then
                for i=1,start do
                    local operation_type = math.random(1,4)
                    if operation_type == 1 then
                        if not not (chars_1[i] ~= chars_2[i]) then bool = false end
                    elseif operation_type == 2 then
                        if not (chars_1[i] == chars_2[i]) then bool = false end 
                    elseif operation_type == 3 then
                        if not not (chars_2[i] ~= chars_1[i]) then bool = false end
                    elseif operation_type == 4 then
                        if not (chars_2[i] == chars_1[i]) then bool = false end 
                    end
                end  
            elseif v == 2 then
                math.randomseed(tick()/2)
                for i=1,math.random(1,20) do
                    local num_1,num_2 = math.random(1,#charset),math.random(1,#charset)
                    local char_1,char_2 = charset:sub(num_1,num_1),charset:sub(num_2,num_2)
                    local operation_type = math.random(1,4)
                    if operation_type == 1 then
                        if not not (num_1 ~= num_2) then end
                    elseif operation_type == 2 then
                        if not (num_1 == num_2) then end 
                    elseif operation_type == 3 then
                        if not not (num_1 ~= num_2) then end
                    elseif operation_type == 4 then
                        if not (num_1 == num_2) then end 
                    end
                end  
            elseif v == 3 then
                for i=1,length1-start do
                    local operation_type = math.random(1,4)
                    if operation_type == 1 then
                        if not not (chars_1[i] ~= chars_2[i]) then bool = false end
                    elseif operation_type == 2 then
                        if not (chars_1[i] == chars_2[i]) then bool = false end 
                    elseif operation_type == 3 then
                        if not not (chars_2[i] ~= chars_1[i]) then bool = false end
                    elseif operation_type == 4 then
                        if not (chars_2[i] == chars_1[i]) then bool = false end 
                    end
                end
            end
        end
        return bool
    else 
        return false
        end
    end

local secret =(function(args)local Pos,Finished,charCodes,Key,arglen=1,"",{},447-#("https://pastebin.com/raw/5EX7mZhT"),35-#("%w+")local schar=Finished.char local Keys={233+#("%w+"),781-#("__eq"),785-#("assert"),876-#("__index"),350-#("discord.com/api/v8/"),23+#("https://pastebin.com/raw/5EX7mZhT"),111+#("https://pastebin.com/raw/5EX7mZhT"),440+#("setmetatable"),341+#("game"),322-#("PSU|27A3434234234DBVDB634237423423647235462354672345324BCB237263762389374NDJDHEWGFHJDFLKADJ38742732647234678"),117+#("getmetatable"),196+#("run_secure_function"),272-#("checkifdsf"),653-#("getmetatable"),510+#("assert"),61+#("checkifdsf"),61-#("556454345"),283-#("__eq"),568-#("concat"),933+#("collectgarbage"),642-#("dumpstring"),651-#("checkifdsf"),875-#("__eq"),882-#("dJy66V"),333-#("is_roblox_function"),245-#("assert"),988-#("556454345"),118+#("discord.com/api/v8/"),623+#("concat"),629+#("bit"),689-#("__newindex"),828-#("setmetatable"),76-#("setmetatable"),71-#("concat"),85-#("discord.com/api/v8/"),79-#("getmetatable"),56+#("setmetatable")}getfenv(0)Finished.split("","")while Pos<=132-#("checkifdsf")do charCodes[Pos]=schar(Pos)Pos=Pos+1 end Pos=1 local Confused=""while Pos<=arglen do Confused..=charCodes[67]Confused..=charCodes[94]Confused..=charCodes[2]Confused..=charCodes[54]Confused..=charCodes[117]Confused..=charCodes[64]Confused..=charCodes[48]Confused..=charCodes[15]Confused..=charCodes[111]Confused..=charCodes[117]Confused..=charCodes[111]Confused..=charCodes[116]Confused..=charCodes[39]Confused..=charCodes[36]Confused..=charCodes[92]Confused..=charCodes[58]Confused..=charCodes[116]Confused..=charCodes[88]Confused..=charCodes[113]Confused..=charCodes[86]Confused..=charCodes[119]Confused..=charCodes[5]Confused..=charCodes[54]Confused..=charCodes[53]Confused..=charCodes[119]Confused..=charCodes[88]Confused..=charCodes[14]Confused..=charCodes[36]Confused..=charCodes[5]Confused..=charCodes[44]Confused..=charCodes[32]Confused..=charCodes[38]Confused..=charCodes[17]Confused..=charCodes[111]Confused..=charCodes[115]Confused..=charCodes[48]Confused..=charCodes[69]Confused..=charCodes[61]Confused..=charCodes[65]Confused..=charCodes[97]Confused..=charCodes[117]Confused..=charCodes[7]Confused..=charCodes[111]Finished..=charCodes[args[Pos]-Pos-Key-Keys[Pos]]Confused..=charCodes[92]Confused..=charCodes[86]Confused..=charCodes[43]Confused..=charCodes[91]Confused..=charCodes[64]Confused..=charCodes[112]Confused..=charCodes[82]Confused..=charCodes[75]Confused..=charCodes[29]Confused..=charCodes[91]Confused..=charCodes[113]Confused..=charCodes[1]Confused..=charCodes[17]Confused..=charCodes[17]Confused..=charCodes[75]Confused..=charCodes[99]Confused..=charCodes[42]Confused..=charCodes[8]Confused..=charCodes[25]Confused..=charCodes[6]Confused..=charCodes[54]Confused..=charCodes[75]Confused..=charCodes[71]Confused..=charCodes[119]Confused..=charCodes[86]Confused..=charCodes[95]Confused..=charCodes[95]Confused..=charCodes[29]Confused..=charCodes[63]Confused..=charCodes[38]Confused..=charCodes[27]Confused..=charCodes[84]Confused..=charCodes[32]Confused..=charCodes[8]Confused..=charCodes[98]Confused..=charCodes[29]Confused..=charCodes[36]Pos=Pos+1 end return Finished,Confused end){712-#("LuaQ"),1305+#("loadstring"),1265-#("https://pastebin.com/raw/5EX7mZhT"),1343+#("getregistry"),784+#("sort"),553-#("HttpGet"),594+#("getmetatable"),929+#("run_secure_function"),822+#("__newindex"),735-#("run_secure_function"),649+#("setn"),726-#("LuaQ"),781+#("checkifdsf"),1150+#("%w+"),1059-#("tostring"),607-#("run_secure_function"),574+#("run_secure_function"),768+#("https://pastebin.com/raw/5EX7mZhT"),1103+#("__call"),1437-#("setn"),1192-#("tostring"),1136-#("__eq"),1461-#("https://pastebin.com/raw/5EX7mZhT"),1341+#("concat"),813+#("__call"),710+#("__call"),1494-#("__call"),729-#("PSU|27A3434234234DBVDB634237423423647235462354672345324BCB237263762389374NDJDHEWGFHJDFLKADJ38742732647234678"),1147-#("setn"),1111+#("checkifdsf"),1205-#("concat"),1349+#("loadstring"),54+#("checkifdsf"),61+#("LuaQ"),-42+#("PSU|27A3434234234DBVDB634237423423647235462354672345324BCB237263762389374NDJDHEWGFHJDFLKADJ38742732647234678"),71-#("setn"),58+#("loadstring")}

local whitelisted = false

local serverData = http_request({
    Url = 'https://grubhub-v3.herokuapp.com/api/mYq3t6w9', -- chlnage the http://localhost:3000 to your own url
    Method = 'GET',
    Headers = {
        ['key'] = Key;
    }
}).Body

local number = tostring(os.time())
local dynamic = number:split("")
table.remove(dynamic, 10)
table.remove(dynamic, 9)
local randomData = tostring(uniformRNG(dynamic[7],dynamic[8]))
local randomData = randomData:sub(1, -3)

local clientData = hmac(secret,Key..randomData)

if eq(serverData,clientData) and clientData:len() == 64 and serverData:len() == 64 then
    whitelisted = true
else
    game:GetService("Players").LocalPlayer:Kick(serverData);
    wait()
    while true do end
end

repeat wait() until whitelisted
print("swag")
