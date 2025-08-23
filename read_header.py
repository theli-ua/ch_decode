import struct
from pathlib import Path
import zlib
from typing import Dict, Any, Tuple, List
from enum import IntFlag
import argparse

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

def swap_byte_order_u64(value: int) -> int:
    return struct.unpack("<Q", struct.pack(">Q", value))[0]

def transform_key(input_key, generator_key):
    generator_key &= 0x1FFFFFFFFF  # 37 bits mask
    intermediate = (input_key ^ generator_key) * 50912195 % 0x2000000000
    mixing_mask = (intermediate ^ (intermediate >> 7)) & 0x550055
    return (intermediate ^ mixing_mask ^ (mixing_mask << 7)) - 1

def parse_song_metadata(header_data: bytes, offset: int = 4) -> Tuple[Dict[str, Any], int]:
    metadata = {}
    
    string_fields = [
        ('chart_file', 'Chart File'),
        ('song_name', 'Song Name'),
        ('artist', 'Artist'),
        ('album', 'Album'),
        ('genre', 'Genre'),
        ('charter', 'Charter'),
        ('year', 'Year'),
        ('additional_info', 'Additional Info')
    ]
    
    for field, display_name in string_fields:
        length = struct.unpack('<I', header_data[offset:offset+4])[0]
        offset += 4
        value = header_data[offset:offset+length].decode('ascii')
        offset += length
        metadata[field] = {'value': value, 'display': display_name}

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

    metadata['song_length'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Song Length'
    }
    offset += 4

    length = struct.unpack('<I', header_data[offset:offset+4])[0]
    offset += 4
    metadata['source'] = {
        'value': header_data[offset:offset+length].decode('ascii'),
        'display': 'Source'
    }
    offset += length

    for i in range(1, 4):
        metadata[f'unknown_int{i}'] = {
            'value': struct.unpack('<I', header_data[offset:offset+4])[0],
            'display': f'Unknown Int {i}'
        }
        offset += 4

    metadata['identifier'] = {
        'value': header_data[offset:offset+16],
        'display': 'Identifier'
    }
    offset += 16

    return metadata, offset

def parse_additional_data(header_data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    additional = {}
    
    additional['chart_data_size'] = {
        'value': struct.unpack('<Q', header_data[offset:offset+8])[0],
        'display': 'Chart Data Size'
    }
    offset += 8

    additional['instrument_count'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Instrument Count'
    }
    offset += 4

    content_flags = ContentFlags(struct.unpack('B', header_data[offset:offset+1])[0])
    additional['content_flags'] = {
        'value': content_flags,
        'display': 'Content Flags'
    }
    offset += 1

    additional['image_count'] = {
        'value': struct.unpack('<I', header_data[offset:offset+4])[0],
        'display': 'Image Count'
    }
    offset += 4

    if ContentFlags.ALBUM_ART in content_flags:
        additional['album_art_index'] = {
            'value': struct.unpack('<I', header_data[offset:offset+4])[0],
            'display': 'Album Art Index'
        }
        offset += 4

    if ContentFlags.BACKGROUND in content_flags:
        additional['background_index'] = {
            'value': struct.unpack('<I', header_data[offset:offset+4])[0],
            'display': 'Background Index'
        }
        offset += 4

    return additional, offset

def write_song_ini(metadata: Dict[str, Any], output_dir: Path):
    ini_path = output_dir / "song.ini"
    with open(ini_path, "w", encoding='utf-8') as f:
        f.write("[Song]\n")
        f.write(f"name = {metadata['song_name']['value']}\n")
        f.write(f"artist = {metadata['artist']['value']}\n")
        f.write(f"album = {metadata['album']['value']}\n")
        f.write(f"genre = {metadata['genre']['value']}\n")
        f.write(f"charter = {metadata['charter']['value']}\n")
        f.write(f"year = {metadata['year']['value']}\n")
        f.write(f"song_length = {metadata['song_length']['value']}\n")
        
        # Write difficulty values
        for field, data in metadata.items():
            if field.startswith('diff_'):
                diff_name = field[5:].replace('ghl', '_ghl')  # Format difficulty names
                if data['value'] >= 0:  # Only write if difficulty is present
                    f.write(f"diff_{diff_name} = {data['value']}\n")

def extract_images(image_data: List[bytes], additional: Dict[str, Any], output_dir: Path):
    content_flags = additional['content_flags']['value']
    
    if ContentFlags.ALBUM_ART in content_flags:
        art_index = additional['album_art_index']['value']
        art_data = image_data[art_index]
        with open(output_dir / "cover.png", "wb") as f:
            f.write(art_data)
            
    if ContentFlags.BACKGROUND in content_flags:
        bg_index = additional['background_index']['value']
        bg_data = image_data[bg_index]
        with open(output_dir / "background.png", "wb") as f:
            f.write(bg_data)

def extract_all(result: Dict[str, Any], output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Write song.ini
    write_song_ini(result['metadata'], output_dir)
    
    # Write chart file
    chart_filename = result['metadata']['chart_file']['value']
    with open(output_dir / chart_filename, "wb") as f:
        f.write(result['chart_data'])
    
    # Extract images if present
    if result['image_data']:
        extract_images(result['image_data'], result['additional'], output_dir)

def print_metadata(metadata: Dict[str, Any], additional: Dict[str, Any]):
    print("\nSong Metadata:")
    print("-" * 75)
    
    print("\nBasic Info:")
    basic_fields = ['chart_file', 'song_name', 'artist', 'album', 'genre', 'charter', 'year', 'additional_info']
    for field in basic_fields:
        if field in metadata:
            print(f"{metadata[field]['display']:15}: {metadata[field]['value']}")
    
    print("\nDifficulty Ratings:")
    diff_fields = [f for f in metadata.keys() if f.startswith('diff_')]
    for field in diff_fields:
        print(f"{metadata[field]['display']:15}: {metadata[field]['value']}")
    
    print("\nTechnical Details:")
    song_length_ms = metadata['song_length']['value']
    print(f"{metadata['song_length']['display']:15}: {song_length_ms} ms ({song_length_ms/1000:.2f} seconds)")
    print(f"{metadata['source']['display']:15}: {metadata['source']['value']}")
    for i in range(1, 4):
        field = f'unknown_int{i}'
        print(f"{metadata[field]['display']:15}: {metadata[field]['value']}")
    print(f"{metadata['identifier']['display']:15}: {metadata['identifier']['value'].hex()}")
    
    print("\nChart & Instrument Info:")
    print(f"{additional['chart_data_size']['display']:15}: {additional['chart_data_size']['value']} bytes")
    print(f"{additional['instrument_count']['display']:15}: {additional['instrument_count']['value']}")

    print("\nContent Info:")
    flags = additional['content_flags']['value']
    print(f"{additional['content_flags']['display']:15}: {flags.name} ({flags.value})")
    print(f"{additional['image_count']['display']:15}: {additional['image_count']['value']}")
    
    if 'album_art_index' in additional:
        print(f"{additional['album_art_index']['display']:15}: {additional['album_art_index']['value']}")
    if 'background_index' in additional:
        print(f"{additional['background_index']['display']:15}: {additional['background_index']['value']}")

def print_arrays(result: Dict[str, Any]):
    if result['image_sizes']:
        print("\nImage Data Sizes:")
        for i, size in enumerate(result['image_sizes']):
            print(f"Image {i}: {size} bytes")
    
    print("\nInstrument Data:")
    for i, (offset, size) in enumerate(zip(result['instrument_offsets'], result['instrument_sizes'])):
        print(f"Instrument {i}: offset={offset}, size={size}")
    
    print(f"\nChart Data Size: {len(result['chart_data'])} bytes")

def read_song_header(filepath: str) -> Dict[str, Any]:
    with open(filepath, 'rb') as f:
        key1 = swap_byte_order_u64(struct.unpack('<Q', f.read(8))[0])
        compressed_size = transform_key(struct.unpack('<Q', f.read(8))[0], key1)
        
        print(f"Header size (key2): {compressed_size}")
        
        compressed_header = f.read(compressed_size)
        decompressor = zlib.decompressobj(-15)
        header_data = decompressor.decompress(compressed_header)
        decompressed_size = len(header_data)
        
        file_version = struct.unpack('<I', header_data[:4])[0]
        print(f"\nFile version: {file_version}")
        
        if file_version != 20210228:
            print("Warning: Unexpected file version!")
        
        print("\nHeader hexdump:")
        print("-" * 75)
        print(hexdump(header_data))
        
        metadata, offset = parse_song_metadata(header_data)
        additional, offset = parse_additional_data(header_data, offset)
        
        # Read image sizes array
        image_sizes = []
        image_data = []
        image_count = additional['image_count']['value']
        image_sizes = []
        if image_count > 0:
            image_sizes = list(struct.unpack(f'<{image_count}Q', header_data[offset:offset + image_count * 8]))
            offset += image_count * 8
        
        # Read instrument arrays
        instrument_count = additional['instrument_count']['value']
        instrument_offsets = list(struct.unpack(f'<{instrument_count}Q', header_data[offset:offset + instrument_count * 8]))
        offset += instrument_count * 8
        
        instrument_sizes = list(struct.unpack(f'<{instrument_count}Q', header_data[offset:offset + instrument_count * 8]))
        offset += instrument_count * 8
        
        # Read and decompress chart data
        chart_data_size = additional['chart_data_size']['value']
        compressed_chart = f.read(chart_data_size)
        chart_data = zlib.decompress(compressed_chart, wbits=-15)

        
        # Read and decompress all images
        for size in image_sizes:
          compressed_image = f.read(size)
          image_data.append(zlib.decompress(compressed_image, wbits=-15))
        
        print_metadata(metadata, additional)
        
        return {
            'decompressed_size': decompressed_size,
            'compressed_size': compressed_size,
            'file_version': file_version,
            'metadata': metadata,
            'additional': additional,
            'next_offset': offset,
            'image_sizes': image_sizes,
            'image_data': image_data,
            'instrument_offsets': instrument_offsets,
            'instrument_sizes': instrument_sizes,
            'chart_data': chart_data
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Clone Hero Song File Parser')
    parser.add_argument('input_file', help='Input song file')
    parser.add_argument('-e', '--extract', help='Extract to directory')
    args = parser.parse_args()
    
    filepath = Path(args.input_file)
    if not filepath.exists():
        print(f"Error: File {filepath} does not exist")
        exit(1)
        
    try:
        result = read_song_header(filepath)
        print("\nSummary:")
        print("-" * 75)
        print(f"Decompressed header size: {result['decompressed_size']} bytes")
        print(f"Compressed header size: {result['compressed_size']} bytes")
        print(f"Next section offset: {result['next_offset']}")
        print_arrays(result)
        
        if args.extract:
            output_dir = Path(args.extract)
            extract_all(result, output_dir)
            print(f"\nExtracted to: {output_dir}")
            
    except Exception as e:
        print(f"Error processing file: {e}")
        exit(1)
