import struct
import json

def make_json_serializable(obj):
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except UnicodeDecodeError:
            return repr(obj)
    elif isinstance(obj, list):
        return [make_json_serializable(i) for i in obj]
    elif isinstance(obj, dict):
        return {make_json_serializable(k): make_json_serializable(v) for k, v in obj.items()}
    return obj

def etf_decode(data: bytes) -> str:
    pos = 0
    objs = []
    
    def read_term():
        nonlocal pos
        tag = data[pos]
        pos += 1
        
        if tag == 97: # SMALL_INTEGER_EXT
            val = data[pos]
            pos += 1
            return val
        elif tag == 98: # INTEGER_EXT
            val = struct.unpack(">i", data[pos:pos+4])[0]
            pos += 4
            return val
        elif tag == 100: # ATOM_EXT
            length = struct.unpack(">H", data[pos:pos+2])[0]
            pos += 2
            val = data[pos:pos+length].decode('latin-1')
            pos += length
            if val == "true": return True
            if val == "false": return False
            if val == "nil": return None
            return val
        elif tag == 106: # NIL_EXT
            return []
        elif tag == 107: # STRING_EXT
            length = struct.unpack(">H", data[pos:pos+2])[0]
            pos += 2
            val = data[pos:pos+length]
            pos += length
            return val
        elif tag == 108: # LIST_EXT
            length = struct.unpack(">I", data[pos:pos+4])[0]
            pos += 4
            lst = []
            for _ in range(length):
                lst.append(read_term())
            tail = read_term() # Tail should be NIL_EXT for proper list
            if tail != []:
                # Improper list, maybe handle differently?
                pass
            return lst
        elif tag == 109: # BINARY_EXT
            length = struct.unpack(">I", data[pos:pos+4])[0]
            pos += 4
            val = data[pos:pos+length]
            pos += length
            return val
        elif tag == 116: # MAP_EXT
            arity = struct.unpack(">I", data[pos:pos+4])[0]
            pos += 4
            m = {}
            for _ in range(arity):
                k = read_term()
                v = read_term()
                m[k] = v
            return m
        elif tag == 110: # SMALL_BIG_EXT
            n = data[pos]
            pos += 1
            sign = data[pos]
            pos += 1
            val_bytes = data[pos:pos+n]
            pos += n
            val = int.from_bytes(val_bytes, byteorder='little')
            if sign == 1:
                val = -val
            return val
        elif tag == 115: # SMALL_ATOM_EXT
            length = data[pos]
            pos += 1
            val = data[pos:pos+length].decode('latin-1')
            pos += length
            if val == "true": return True
            if val == "false": return False
            if val == "nil": return None
            return val
        else:
            raise ValueError(f"Unknown tag: {tag} at pos {pos-1}")

    while pos < len(data):
        if data[pos] != 131:
            # If it's not 131, it might not be ETF or we are misaligned.
            # For now, raise error as in the reference implementation.
            raise ValueError(f"Not an ETF stream at pos {pos}")
        pos += 1
        objs.append(read_term())

    # Convert to JSON serializable structure
    serializable_objs = make_json_serializable(objs)
    
    # Return as JSON string
    # If there is only one object, maybe return just that? 
    # The reference implementation printed all objects.
    # I'll return the list of objects as a JSON array string.
    return json.dumps(serializable_objs)
