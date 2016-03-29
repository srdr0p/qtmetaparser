from idc import *
from idaapi import offflag


def struct_adder(cls, mapper):
    if GetStrucIdByName(cls.__name__) == BADADDR:
        idx = GetLastStrucIdx() + 1
        sid = AddStruc(idx, cls.__name__)
        cls.sid = sid
        for member in mapper:
            type_flag = member[1]
            if isOff0(type_flag):
                AddStrucMember(sid, member[0], -1, type_flag, 0, get_bytes_size(type_flag))
            else:
                AddStrucMember(sid, member[0], -1, type_flag, -1, get_bytes_size(type_flag))
    else:
        cls.sid = GetStrucIdByName(cls.__name__)


def struct_maker(obj, off):
    struct_adder(obj.__class__, obj.c_struct)
    MakeUnknown(off, GetStrucSize(obj.__class__.sid), DOUNK_EXPAND)
    MakeStruct(off, GetStrucName(obj.__class__.sid))


# noinspection PyPep8Naming
class QMetaObjectPrivate:
    """
struct QMetaObjectPrivate
{
    // revision 7 is Qt 5.0 everything lower is not supported
    enum { OutputRevision = 7 }; // Used by moc, qmetaobjectbuilder and qdbus

    int revision;
    int className;
    int classInfoCount, classInfoData;
    int methodCount, methodData;
    int propertyCount, propertyData;
    int enumeratorCount, enumeratorData;
    int constructorCount, constructorData;
    int flags;
    int signalCount;
    enum DisconnectType { DisconnectAll, DisconnectOne };
};

QMetaMethod QMetaObject::method(int index) const
{
    int i = index;
    i -= methodOffset();
    if (i < 0 && d.superdata)
        return d.superdata->method(index);

    QMetaMethod result;
    if (i >= 0 && i < priv(d.data)->methodCount) {
        result.mobj = this;
        result.handle = priv(d.data)->methodData + 5*i;
    }
    return result;
}


"""
    c_struct = [("revision", FF_DATA | FF_DWRD),
                ("className", FF_DATA | FF_DWRD),
                ("classInfoCount", FF_DATA | FF_DWRD),
                ("classInfoData", FF_DATA | FF_DWRD),
                ("methodCount", FF_DATA | FF_DWRD),
                ("methodData", FF_DATA | FF_DWRD),
                ("propertyCount", FF_DATA | FF_DWRD),
                ("propertyData", FF_DATA | FF_DWRD),
                ("enumeratorCount", FF_DATA | FF_DWRD),
                ("enumeratorData", FF_DATA | FF_DWRD),
                ("constructorCount", FF_DATA | FF_DWRD),
                ("constructorData", FF_DATA | FF_DWRD),
                ("flags", FF_DATA | FF_DWRD),
                ("signalCount", FF_DATA | FF_DWRD)]

    # todo: when superdata is not null
    def __init__(self, offset, str_data):
        self.offset = offset
        struct_map(self, self.c_struct, offset)
        struct_maker(self, offset)
        MakeComm(offset, "CLASS: %s" % str_data[self.className].string)


def displayMetaData(data_addr):
    parser = QtMetaParser(data_addr)
    parser.make_qmetaobjecprivate()
    pass


# TODO: when superdata is not null
class QtMetaParser:
    def __init__(self, d_offset):
        self.d_offset = d_offset
        self.d = QMetaObject__d(d_offset)
        self.str_data = self.get_str_data(self.d.stringdata)
        self.qmeta_obj_pri = QMetaObjectPrivate(self.d.data, self.str_data)
        class_name = self.str_data[self.qmeta_obj_pri.className].string
        class_spc = class_name + "::"
        MakeName(d_offset, class_name)
        MakeName(self.d.stringdata, class_spc + "stringdata")
        MakeName(self.d.data, class_spc + "data")
        if not Name(self.d.metacall).startswith("nullsub"):
            MakeName(self.d.metacall, class_spc + "metacall")

    @staticmethod
    def get_str_data(str_off):
        start = str_off
        str_data = []
        while Dword(start) == 0xFFFFFFFF and Dword(start + 8) == 0:
            str_data.append(QArrayData(start))
            start += 16
        return str_data

    def make_qmetaobjecprivate(self):
        # parse method
        start = self.qmeta_obj_pri.offset + (self.qmeta_obj_pri.methodData << 2)
        method_data = []
        for off in range(start, start + 4 * 5 * self.qmeta_obj_pri.methodCount, 4 * 5):
            qmthd = QMetaMethod(off, self.str_data)
            # MakeComm(qmthd.offset, "METHOD_%d " % len(method_data) + Comment(qmthd.offset))
            method_data.append(qmthd)


class Enum:
    def __init__(self, **entries): self.__dict__.update(entries)


class QMetaMethod:
    c_struct = [("name", FF_DATA | FF_DWRD),
                ("parameterCount", FF_DATA | FF_DWRD),
                ("typesDataIndex", FF_DATA | FF_DWRD),
                ("tag", FF_DATA | FF_DWRD),
                ("flag", FF_DATA | FF_DWRD)]
    QMetaMethodOff = {"name": 0, "parameterCount": 4, "typesDataIndex": 8, "tag": 12, "flag": 16}
    PropertyFlags = Enum(
        Invalid=0x00000000,
        Readable=0x00000001,
        Writable=0x00000002,
        Resettable=0x00000004,
        EnumOrFlag=0x00000008,
        StdCppSet=0x00000100,
        Override=0x00000200,
        Constant=0x00000400,
        Final=0x00000800,
        Designable=0x00001000,
        ResolveDesignable=0x00002000,
        Scriptable=0x00004000,
        ResolveScriptable=0x00008000,
        Stored=0x00010000,
        ResolveStored=0x00020000,
        Editable=0x00040000,
        ResolveEditable=0x00080000,
        User=0x00100000,
        ResolveUser=0x00200000,
        Notify=0x00400000,
        Revisioned=0x00800000
    )
    MethodFlags = Enum(
        AccessPrivate=0x00,
        AccessProtected=0x01,
        AccessPublic=0x02,
        AccessMask=0x03,

        MethodMethod=0x00,
        MethodSignal=0x04,
        MethodSlot=0x08,
        MethodConstructor=0x0c,
        MethodTypeMask=0x0c,

        MethodCompatibility=0x10,
        MethodCloned=0x20,
        MethodScriptable=0x40,
        MethodRevisioned=0x80
    )
    MethodTypesDict = {0x00: "METHOD",
                       0x04: "SIGNAL",
                       0x08: "SLOT",
                       0x0c: "CONSTRUCTOR",
                       }
    MethodAccessDict = {0x00: "Private",
                        0x01: "Protected",
                        0x02: "Public"}

    def get_type_str(self):
        method_type = self.flag & self.MethodFlags.MethodTypeMask
        cmmt = self.MethodTypesDict[method_type]
        access = self.flag & self.MethodFlags.AccessMask
        cmmt += " " + self.MethodAccessDict[access]
        if self.flag & self.MethodFlags.MethodCompatibility:
            cmmt += " Compatibility"
        elif self.flag & self.MethodFlags.MethodCloned:
            cmmt += " Cloned"
        elif self.flag & self.MethodFlags.MethodScriptable:
            cmmt += " Sciptable"
        elif self.flag & self.MethodFlags.MethodRevisioned:
            cmmt += " Revisioned"
        return cmmt

    def __init__(self, off, str_data):
        self.offset = off
        struct_map(self, self.c_struct, off)
        struct_maker(self, off)
        MakeComm(off, str_data[self.name].string + self.get_type_str())


def get_bytes_size(data_flag):
    if isByte(data_flag):
        bytes_len = 1
    elif isWord(data_flag):
        bytes_len = 2
    elif isDwrd(data_flag):
        bytes_len = 4
    return bytes_len


def struct_map(obj, stru, off):
    type_maker = {1: Byte, 2: Word, 4: Dword}
    for member in stru:
        bytes_len = get_bytes_size(member[1])
        setattr(obj, member[0], type_maker[bytes_len](off))
        # MakeUnknown(off, bytes_len, DOUNK_EXPAND)
        # type_maker[mem_len](off)
        # MakeComm(off, member[0])
        off += bytes_len
    return off


class QMetaObject__d:
    """
struct QMetaObject::d { // private data
    const QMetaObject *superdata;
    const QByteArrayData *stringdata;
    const uint *data;
    StaticMetacallFunction static_metacall;
    const QMetaObject * const *relatedMetaObjects;
    void *extradata; //reserved for future use
} d;
"""
    c_struct = [("superdata", offflag() | FF_DATA | FF_DWRD),
                ("stringdata", offflag() | FF_DATA | FF_DWRD),
                ("data", offflag() | FF_DATA | FF_DWRD),
                ("metacall", offflag() | FF_DATA | FF_DWRD),
                ("relatedMetaObjects", offflag() | FF_DATA | FF_DWRD),
                ("extradata", offflag() | FF_DATA | FF_DWRD)]

    def __init__(self, offset):
        struct_map(self, self.c_struct, offset)
        struct_maker(self, offset)


class QArrayData:
    """
struct QArrayData
{
    QtPrivate::RefCount ref;
    int size;
    uint alloc : 31;
    uint capacityReserved : 1;

    qptrdiff offset; // in bytes from beginning of header
};
static inline const QByteArray stringData(const QMetaObject *mo, int index)
{
    Q_ASSERT(priv(mo->d.data)->revision >= 7);
    const QByteArrayDataPtr data = { const_cast<QByteArrayData*>(&mo->d.stringdata[index]) };
    Q_ASSERT(data.ptr->ref.isStatic());
    Q_ASSERT(data.ptr->alloc == 0);
    Q_ASSERT(data.ptr->capacityReserved == 0);
    Q_ASSERT(data.ptr->size >= 0);
    return data;
}

"""

    def __init__(self, ptr):
        self.ptr = ptr
        self.ref = Dword(ptr)
        MakeComm(ptr, "ref")
        MakeDword(ptr)
        ptr += 4
        self.size = Dword(ptr)
        MakeComm(ptr, "size")
        MakeDword(ptr)
        ptr += 4
        alloc_size = Dword(ptr)
        self.alloc = 0x7FFFFFFF & alloc_size
        self.capacityReserved = alloc_size >> 31
        MakeComm(ptr, "alloc: %d, capRvrsd %d" % (self.alloc, self.capacityReserved))
        MakeDword(ptr)
        ptr += 4
        self.offset = Dword(ptr)
        self.string = GetString(self.ptr + self.offset)
        MakeStr(self.ptr + self.offset, BADADDR)
        MakeComm(ptr, "String: %s" % self.string)
        MakeDword(ptr)

    def __repr__(self):
        return "%s" % self.string


addrtoparse = ScreenEA()
if addrtoparse != 0:
    displayMetaData(addrtoparse)
