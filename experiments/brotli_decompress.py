import brotli  # pip install brotli

hex_str = "210350060040fe4fcf69edfb05b59117e31257e09013f503c041c34c9b071b638e2f346e5003049e98f07c57e57d18e6aec5df8e440eb3bcbe54024b17548fb75d8166311e07cadf0f91f90a0e3c25871034fbfd6e1bc8d2b7d36af6fab5410b21c9e1fc1757c418dbaeef8d57e7fdaeb283d473d92f348fd171cdc100999225302dbf5d9bc300a16409f6f5f6ea8e618020f9cfe6ff7f323f340003"  # your hex string here (no 0x, only hex chars)

# 1. Hex string → bytes
compressed_bytes = bytes.fromhex(hex_str)

# 2. Brotli decompress
# Use Decompressor because the stream might be incomplete or have extra data
decompressor = brotli.Decompressor()
decompressed_bytes = decompressor.process(compressed_bytes)

# 3. If it's text, decode to string (usually UTF-8)
text = decompressed_bytes.decode("utf-8")

print(text)
