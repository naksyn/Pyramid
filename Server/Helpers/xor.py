def xor(data, key):
    xored_data = []
    i = 0
    for data_byte in data:
        if i < len(key):
            xored_byte = data_byte ^ key[i]
            xored_data.append(xored_byte)
            i += 1
        else:
            xored_byte = data_byte ^ key[0]
            xored_data.append(xored_byte)
            i = 1
    return bytes(xored_data)

