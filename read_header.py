import struct
from pathlib import Path
import zlib
from typing import Dict, Any, Tuple
from enum import IntFlag

class ContentFlags(IntFlag):
    NONE = 0
    ALBUM_ART = 1
    BACKGROUND = 2

def hexdump(data, offset=0, length=None, width=16):
    def printable(b):
        return chr(b) if 32 <= b <= 126 else '.'

    if length is None:
        length = len(data)
    
    result = []
    for i in range(0, length, width):
        chunk = data[i:i+width]
        hex_line = ' '.join(f'{b:02x}' for b in chunk)
        hex_line = hex_line.ljust(width * 3 - 1)
        ascii_line = ''.join(printable(b) for b in chunk)
        result.append(f"{offset+i:08x}  {hex_line}  |{ascii_line}|")
    
    return '\n'.join(result)

def swap_byte_order_u64(value):
    return struct.unpack("<Q", struct.pack(">Q", value))[0]

def transform_key(input_key, generator_key):
    generator_key &= 0x1FFFFFFFFF  # 37 bits mask
    intermediate = (input_key ^ generator_key) * 50912195 % 0x2000000000
    mixing_mask = (intermediate ^ (intermediate >> 7)) & 0x54E6E5
    return (intermediate ^ mixing_mask ^ (mixing_mask << 7)) - 1

def parse_song_metadata(header_data: bytes, offset: int = 4) -> Tuple[Dict[str, Any], int]:
    metadata = {}
    
    # Read strings with correct field names
    string_fields = [
        ('chart_file', 'Chart File'),    # notes.mid
        ('song_name', 'Song Name'),      # Moonhunter
        ('artist', 'Artist'),            # Echoflesh
        ('album', 'Album'),             # Moonhunter (Single)
        ('genre', 'Genre'),             # Progressive Rock
        ('charter', 'Charter'),         # Drihscol
        ('year', 'Year'),               # 2020
        ('additional_info', 'Additional Info')  # A spooky song...
    ]
    
    for field, display_name in string_fields:
        length = struct.unpack('<I', header_data[offset:offset+4])[0]
        offset += 4
        value = header_data[offset:offset+length].decode('ascii')
        offset += length
        metadata[field] = {'value': value, 'display': display_name}

    # Read difficulty values (signed bytes)
    diff_fields = [
        ('diff_band', 'Band'),
        ('diff_guitar', 'Guitar'),
        ('diff_bass', 'Bass'),
        ('diff_rhythm', 'Rhythm'),
        ('diff_drums', 'Drums'),
        ('diff_keys', 'Keys'),
        ('diff_guitarghl', 'Guitar GHL'),
        ('diff_bassghl', 'Bass GHL'),
        ('diff_rhythmghl', 'Rhythm GHL'),
        ('diff_drumreal', 'Drums Real'),
        ('diff_drumsex', 'Drums Expert'),
        ('diff_keys_real', 'Keys Real')
    ]
    
    for field, display_name in diff_fields:
        metadata[field] = {
            'value': struct.unpack('b', header_data[offset:offset+1])[0],
            'display': display_name
        }
        offset += 1

    # Read song length
    metadata['song_length'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Song Length'
    }
    offset += 4

    # Read source string
    length = struct.unpack('<I', header_data[offset:offset+4])[0]
    offset += 4
    metadata['source'] = {
        'value': header_data[offset:offset+length].decode('ascii'),
        'display': 'Source'
    }
    offset += length

    # Unknown integers
    metadata['unknown_int1'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Unknown Int 1'
    }
    offset += 4
    
    metadata['unknown_int2'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Unknown Int 2'
    }
    offset += 4

    metadata['unknown_int3'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Unknown Int 3'
    }
    offset += 4

    # Read 16-byte identifier
    metadata['identifier'] = {
        'value': header_data[offset:offset+16],
        'display': 'Identifier'
    }
    offset += 16

    # Read 8-byte long (audio data size)
    metadata['audio_data_size'] = {
        'value': struct.unpack('<Q', header_data[offset:offset+8])[0],
        'display': 'Audio Data Size'
    }
    offset += 8

    # Read 4-byte int (instrument count)
    metadata['instrument_count'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Instrument Count'
    }
    offset += 4

    # Read content flags (1 byte)
    content_flags = ContentFlags(struct.unpack('B', header_data[offset:offset+1])[0])
    metadata['content_flags'] = {
        'value': content_flags,
        'display': 'Content Flags'
    }
    offset += 1

    # Read difficulties present count (4 bytes)
    metadata['difficulties_present'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Difficulties Present'
    }
    offset += 4

    # Read optional content offsets based on flags
    if ContentFlags.ALBUM_ART in content_flags:
        metadata['album_art_offset'] = {
            'value': struct.unpack('<I', header_data[offset:offset+4])[0],
            'display': 'Album Art Offset'
        }
        offset += 4

    if ContentFlags.BACKGROUND in content_flags:
        metadata['background_offset'] = {
            'value': struct.unpack('<I', header_data[offset:offset+4])[0],
            'display': 'Background Offset'
        }
        offset += 4

    return metadata, offset

def print_metadata(metadata: Dict[str, Any]):
    print("\nSong Metadata:")
    print("-" * 75)
    
    # Print basic song info
    print("\nBasic Info:")
    basic_fields = ['chart_file', 'song_name', 'artist', 'album', 'genre', 'charter', 'year', 'additional_info']
    for field in basic_fields:
        if field in metadata:
            print(f"{metadata[field]['display']:15}: {metadata[field]['value']}")
    
    # Print difficulty ratings
    print("\nDifficulty Ratings:")
    diff_fields = [f for f in metadata.keys() if f.startswith('diff_')]
    for field in diff_fields:
        print(f"{metadata[field]['display']:15}: {metadata[field]['value']}")
    
    # Print technical details
    print("\nTechnical Details:")
    song_length_ms = metadata['song_length']['value']
    print(f"{metadata['song_length']['display']:15}: {song_length_ms} ms ({song_length_ms/1000:.2f} seconds)")
    print(f"{metadata['source']['display']:15}: {metadata['source']['value']}")
    print(f"{metadata['unknown_int1']['display']:15}: {metadata['unknown_int1']['value']}")
    print(f"{metadata['unknown_int2']['display']:15}: {metadata['unknown_int2']['value']}")
    print(f"{metadata['unknown_int3']['display']:15}: {metadata['unknown_int3']['value']}")
    print(f"{metadata['identifier']['display']:15}: {metadata['identifier']['value'].hex()}")
    
    # Print audio and instrument info
    print("\nAudio & Instrument Info:")
    print(f"{metadata['audio_data_size']['display']:15}: {metadata['audio_data_size']['value']} bytes")
    print(f"{metadata['instrument_count']['display']:15}: {metadata['instrument_count']['value']}")

    # Print content flags and offsets
    print("\nContent Info:")
    flags = metadata['content_flags']['value']
    print(f"{metadata['content_flags']['display']:15}: {flags.name} ({flags.value})")
    
    if 'album_art_offset' in metadata:
        print(f"{metadata['album_art_offset']['display']:15}: {metadata['album_art_offset']['value']}")
    if 'background_offset' in metadata:
        print(f"{metadata['background_offset']['display']:15}: {metadata['background_offset']['value']}")
    
    print(f"{metadata['difficulties_present']['display']:15}: {metadata['difficulties_present']['value']}")

def read_song_header(filepath: str) -> Dict[str, Any]:
    with open(filepath, 'rb') as f:
        # Read encryption keys
        key1 = swap_byte_order_u64(struct.unpack('<Q', f.read(8))[0])
        key2 = transform_key(struct.unpack('<Q', f.read(8))[0], key1)
        
        print(f"Header size (key2): {key2}")
        
        # Read compressed header
        compressed_header = f.read(key2)
        
        # Decompress header using raw deflate
        decompressor = zlib.decompressobj(-15)
        header_data = decompressor.decompress(compressed_header)
        
        # Read file version (uint32)
        file_version = struct.unpack('<I', header_data[:4])[0]
        
        print(f"\nFile version: {file_version}")
        
        if file_version != 20210228:
            print("Warning: Unexpected file version!")
        
        print("\nHeader hexdump:")
        print("-" * 75)
        print(hexdump(header_data))
        
        # Parse metadata
        metadata, next_offset = parse_song_metadata(header_data)
        print_metadata(metadata)
        
        return {
            'header_size': key2,
            'file_version': file_version,
            'decompressed_size': len(header_data),
            'metadata': metadata,
            'next_offset': next_offset
        }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_song_file>")
        sys.exit(1)
        
    filepath = Path(sys.argv[1])
    if not filepath.exists():
        print(f"Error: File {filepath} does not exist")
        sys.exit(1)
        
    try:
        result = read_song_header(filepath)
        print("\nSummary:")
        print("-" * 75)
        print(f"Compressed header size: {result['header_size']} bytes")
        print(f"Decompressed header size: {result['decompressed_size']} bytes")
        print(f"Next section offset: {result['next_offset']}")
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)

