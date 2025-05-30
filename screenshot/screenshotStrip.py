import binascii
import os

# RE-RE-TRANSCRIBED hex data from the screenshot.
# Each line in the screenshot is 16 bytes (32 hex characters).
# The last line (000000e0) only shows 13 bytes (26 hex characters).
hex_data_from_dump = (
    "504b03040a00010063002f02b55a0000" # 00000000
    "430000002700000008000b00666c6167" # 00000010
    "2e7478740100020041450300003d42ff" # 00000020
    "1db35f95031424f68b65c3f57669f14e" # 00000030
    "8df0003fe240b3ac3364859e4c2dbc3c" # 00000040
    "36f2d4ac403761385af6e4e3f90fbdd2" # 00000050
    "9d91b614ba2c6efde11b71bccc90707a7" # 00000060
    "2ed504b01023f030300010063002f02b" # 00000070
    "55a0000430000002700000008000b000" # 00000080 - Appears to be `55a0000 4300 0000 2700 0000 0800 0b00 0` - which is 31 chars?
    "0000000000002080b4810000666c6167" # 00000090
    "2e7478740a0020000000000001001800" # 000000a0
    "8213854307ca0db01000000000000000" # 000000b0 - This one ends in 0, screenshot shows 31.
    "000000000000000000000199"         # 000000c0 - This is 24 chars.
    "070002004145030000504b0506000000" # 000000d0
    "000000000000010001006500000074000000" # 000000e0 - Ends at '00'. The image shows '00' at the very end. This is 32 chars.
)

# Let's count characters again carefully for each line based on the visual screenshot.
# The '000000e0' line in the image is: '0001 0001 0065 0000 0074 0000 00'
# This translates to '00010001006500000074000000' which is 26 characters.

# Let's re-assemble using what I actually see:
hex_data_from_dump = (
    "504b03040a00010063002f02b55a0000" + # 32 chars
    "430000002700000008000b00666c6167" + # 32 chars
    "2e7478740100020041450300003d42ff" + # 32 chars
    "1db35f95031424f68b65c3f57669f14e" + # 32 chars
    "8df0003fe240b3ac3364859e4c2dbc3c" + # 32 chars
    "36f2d4ac403761385af6e4e3f90fbdd2" + # 32 chars
    "9d91b614ba2c6efde11b71bccc90707a7" + # 32 chars
    "2ed504b01023f030300010063002f02b" + # 32 chars
    "55a0000430000002700000008000b000" + # 32 chars (This one is `55a0 0004 3000 0002 7000 0000 8000 b000`)
    "0000000000002080b4810000666c6167" + # 32 chars
    "2e7478740a0020000000000001001800" + # 32 chars
    "8213854307ca0db01000000000000000" + # 31 chars in image. This means last byte is missing for some reason.
    "000000000000000000000199" +         # 24 chars in image.
    "070002004145030000504b0506000000" + # 32 chars
    "000000000000010001006500000074000000" # 26 chars in image. (`00010001006500000074000000`)
)

# Total length of these combined sections:
# 32 * 11 + 31 + 24 + 32 + 26 = 352 + 31 + 24 + 32 + 26 = 465 chars. Still odd.

# The issue is most likely a single missing or extra character.
# Let's try adding one '0' at the end of the problematic lines to make them even.
# It's typical for hex dumps to represent full bytes.
# The '000000b0' line is `8213854307ca0db01000000000000000` (31 characters). It *should* be `8213854307ca0db010000000000000000` (32 characters).
# The '000000e0' line is `00010001006500000074000000` (26 characters). This seems to be the very end of the file. It might be correct if the file truly ends there.

# Let's focus on the '000000b0' line. The screenshot clearly shows it ends with `000000000000000`. If this is truly `15` hex characters then it's wrong.
# A common issue with hex dumps is that if the last byte is `0`, it might be represented as `0` instead of `00`.
# However, given the output format, it should always be two hex characters per byte.

# Let's verify the source of the screenshot. If it's a tool like `xxd` or `hexdump`,
# it should always provide an even number of hex characters per byte.
# The screenshot shows `000000b0: 8213 8543 07ca 0db0 1000 0000 0000 000`. The last `0` is the issue.
# It means that the last byte is `0` but is missing its pair `0`. It should be `00`.
# So, `8213854307ca0db01000000000000000` should be `8213854307ca0db010000000000000000`. (32 chars)

# Now, the '000000e0' line: `0001 0001 0065 0000 0074 0000 00` (26 chars).
# This corresponds to 13 bytes. A zip file can end with an arbitrary number of bytes.
# So, this line length could be legitimate for the end of a file.

# Let's retry with the corrected 'b0' line:
hex_data_from_dump = (
    "504b03040a00010063002f02b55a0000" + # 32 chars
    "430000002700000008000b00666c6167" + # 32 chars
    "2e7478740100020041450300003d42ff" + # 32 chars
    "1db35f95031424f68b65c3f57669f14e" + # 32 chars
    "8df0003fe240b3ac3364859e4c2dbc3c" + # 32 chars
    "36f2d4ac403761385af6e4e3f90fbdd2" + # 32 chars
    "9d91b614ba2c6efde11b71bccc90707a7" + # 32 chars
    "2ed504b01023f030300010063002f02b" + # 32 chars
    "55a0000430000002700000008000b000" + # 32 chars
    "0000000000002080b4810000666c6167" + # 32 chars
    "2e7478740a0020000000000001001800" + # 32 chars
    "8213854307ca0db010000000000000000" + # CORRECTED: Added a '0' to make it 32 chars
    "000000000000000000000199" +         # 24 chars
    "070002004145030000504b0506000000" + # 32 chars
    "000000000000010001006500000074000000"  # 26 chars
)

print(len(hex_data_from_dump))

import binascii
import os

# RE-RE-RE-TRANSCRIBED hex data from the screenshot, character by character.
# Each line in the screenshot's hex dump should be exactly 16 bytes (32 hex characters)
# unless it's the very last line of the file.
hex_data_from_dump = (
    "504b03040a00010063002f02b55a0000" + # Line 00000000
    "430000002700000008000b00666c6167" + # Line 00000010
    "2e7478740100020041450300003d42ff" + # Line 00000020
    "1db35f95031424f68b65c3f57669f14e" + # Line 00000030
    "8df0003fe240b3ac3364859e4c2dbc3c" + # Line 00000040
    "36f2d4ac403761385af6e4e3f90fbdd2" + # Line 00000050
    "9d91b614ba2c6efde11b71bccc90707a7" + # Line 00000060
    "2ed504b01023f030300010063002f02b" + # Line 00000070
    "55a0000430000002700000008000b000" + # Line 00000080 (Matches `55a0 0004 3000 0002 7000 0000 8000 b000`)
    "0000000000002080b4810000666c6167" + # Line 00000090
    "2e7478740a0020000000000001001800" + # Line 000000a0
    "8213854307ca0db01000000000000000" + # Line 000000b0 (Ends with single '0' in screenshot, which means it should be '00'. Corrected to 32 chars)
    "000000000000000000000199" +         # Line 000000c0 (24 chars)
    "070002004145030000504b0506000000" + # Line 000000d0
    "000000000000010001006500000074000000"  # Line 000000e0 (26 chars, matches screenshot exactly)
)

# Correct the '000000b0' line based on standard hex dump formatting conventions where
# a single '0' at the end of a byte means it was implicitly '00'.
hex_data_from_dump_corrected_b0 = (
    "504b03040a00010063002f02b55a0000" +
    "430000002700000008000b00666c6167" +
    "2e7478740100020041450300003d42ff" +
    "1db35f95031424f68b65c3f57669f14e" +
    "8df0003fe240b3ac3364859e4c2dbc3c" +
    "36f2d4ac403761385af6e4e3f90fbdd2" +
    "9d91b614ba2c6efde11b71bccc90707a7" +
    "2ed504b01023f030300010063002f02b" +
    "55a0000430000002700000008000b000" +
    "0000000000002080b4810000666c6167" +
    "2e7478740a0020000000000001001800" +
    "8213854307ca0db010000000000000000" + # CORRECTED: Added a '0' to make it 32 chars (original was 31 in screenshot)
    "000000000000000000000199" +
    "070002004145030000504b0506000000" +
    "000000000000010001006500000074000000"
)

output_zip_filename = "flag.zip"

print(f"Length of hex_data_from_dump_corrected_b0: {len(hex_data_from_dump_corrected_b0)}")

try:
    binary_data = binascii.unhexlify(hex_data_from_dump_corrected_b0)
    with open(output_zip_filename, "wb") as f:
        f.write(binary_data)
    print(f"Successfully reconstructed '{output_zip_filename}' from hexadecimal data.")

except binascii.Error as e:
    print(f"Error converting hex to binary: {e}")
    print("Please double-check that the hexadecimal data is correctly copied and formatted.")
except IOError as e:
    print(f"Error writing to file '{output_zip_filename}': {e}")