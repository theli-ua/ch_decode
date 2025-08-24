import struct
from pathlib import Path
import zlib
from typing import Dict, Any, Tuple, List
from enum import IntFlag
import argparse

# Try to import AES - fallback to manual implementation if not available
try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False
        print("Warning: No crypto library found. Install pycryptodome or cryptography for audio decryption.")
        print("  pip install pycryptodome")
        print("  or")
        print("  pip install cryptography")

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

def generate_aes_key():
    """Generate the deterministic AES key used by Clone Hero"""
    def pseudo_random(value):
        return (value * 1664525 + 1013904223) & 0xFFFFFFFFFFFFFFFF
    
    def generate_constant(multiplier):
        base_value = 0xFFFFFFFFFFFFFFFF // (multiplier << 19)
        return pseudo_random(((base_value & 0xFF00FF00FF00FF00) >> 1) ^ 
                           ((base_value & 0x00FF00FF00FF00FF) << 1))
    
    def swap_bits(value1, value2):
        for i in range(int(((value1 ^ value2) & 0x3F)) + 1):
            mask1 = value1 & (0xF << i)
            mask2 = value2 & (0xF << i)
            value1 ^= (0xF << i)
            value2 ^= (0xF << i)
            value1 |= mask2
            value2 |= mask1
        return value1, value2
    
    # Generate the two constants
    value1 = generate_constant(5)
    value2 = generate_constant(11)
    
    # Swap bits
    value1, value2 = swap_bits(value1, value2)
    
    # Pack into 16-byte key
    key = struct.pack('<QQ', value1, value2)
    return key

def parse_audio_header(data):
    """Parse the 32-byte audio header"""
    if len(data) < 32:
        raise ValueError("Audio header must be at least 32 bytes")
    
    instrument_type = struct.unpack('<I', data[0:4])[0]
    reserved = struct.unpack('<I', data[4:8])[0]
    encryption_key1 = struct.unpack('<Q', data[8:16])[0]
    encryption_key2 = struct.unpack('<Q', data[16:24])[0]
    audio_data_size = struct.unpack('<Q', data[24:32])[0] & 0x7FFFFFFFFFFFFFFF  # Clear sign bit
    
    return {
        'instrument_type': instrument_type,
        'reserved': reserved,
        'encryption_key1': encryption_key1,
        'encryption_key2': encryption_key2,
        'audio_data_size': audio_data_size
    }

def get_instrument_name(instrument_type):
    """Map instrument type to name"""
    instrument_names = {
        0: 'rhythm',
        1: 'guitar', 
        2: 'bass',
        3: 'vocals',
        4: 'vocals_1',
        5: 'vocals_2', 
        6: 'drums',
        7: 'drums_1',
        8: 'drums_2',
        9: 'drums_3',
        10: 'drums_4',
        11: 'keys',
        12: 'song',
        13: 'crowd'
    }
    return instrument_names.get(instrument_type, f'unknown_{instrument_type}')

def aes_encrypt_block(key, plaintext):
    """Encrypt a single AES block using available crypto library"""
    if not HAS_CRYPTO:
        raise RuntimeError("No crypto library available for AES encryption")
    
    try:
        # Try pycryptodome first
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)
    except ImportError:
        # Try cryptography library
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_audio_data(encrypted_data, encryption_key1, encryption_key2, aes_key):
    """Decrypt audio data using AES in custom streaming mode"""
    if len(encrypted_data) == 0:
        return b''
    
    if not HAS_CRYPTO:
        print("Warning: Cannot decrypt audio data - no crypto library available")
        return encrypted_data  # Return encrypted data as-is
    
    decrypted_data = bytearray()
    
    # Process data in 16-byte blocks
    for block_start in range(0, len(encrypted_data), 16):
        block_end = min(block_start + 16, len(encrypted_data))
        encrypted_block = encrypted_data[block_start:block_end]
        
        # Generate keystream for this block
        if block_start == 0:
            # First block: use encryption keys from header
            keystream_input = struct.pack('<QQ', encryption_key2, encryption_key1)
        else:
            # Subsequent blocks: use previous 16 bytes of encrypted data
            prev_block_start = max(0, block_start - 16)
            prev_block_end = prev_block_start + 16
            keystream_input = encrypted_data[prev_block_start:prev_block_end]
            
            # Pad if necessary
            if len(keystream_input) < 16:
                keystream_input += b'\x00' * (16 - len(keystream_input))
        
        # Generate keystream by encrypting the input
        keystream = aes_encrypt_block(aes_key, keystream_input)
        
        # XOR encrypted data with keystream
        for i in range(len(encrypted_block)):
            decrypted_data.append(encrypted_block[i] ^ keystream[i])
    
    return bytes(decrypted_data)

def check_file_type(filepath):
    """Use the 'file' command to check file type"""
    import subprocess
    try:
        result = subprocess.run(['file', str(filepath)], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None

def extract_audio_data(filepath: str, instrument_offsets: List[int], instrument_sizes: List[int], 
                      output_dir: Path, file_handle=None):
    """Extract and decrypt audio data from the .sng file"""
    aes_key = generate_aes_key()
    print(f"\nGenerated AES key: {aes_key.hex()}")
    
    # Calculate the current file position after reading header, chart, and images
    if file_handle is None:
        with open(filepath, 'rb') as f:
            return extract_audio_data(filepath, instrument_offsets, instrument_sizes, output_dir, f)
    
    audio_info = []
    
    for i, (offset, size) in enumerate(zip(instrument_offsets, instrument_sizes)):
        if size == 0:
            continue
            
        print(f"\nProcessing instrument {i}: offset={offset}, size={size}")
        
        # Seek to the audio data location
        file_handle.seek(offset)
        
        # Read the 32-byte header
        header_data = file_handle.read(32)
        if len(header_data) < 32:
            print(f"Warning: Could not read full header for instrument {i}")
            continue
            
        try:
            header = parse_audio_header(header_data)
            instrument_name = get_instrument_name(header['instrument_type'])
            
            print(f"  Instrument type: {header['instrument_type']} ({instrument_name})")
            print(f"  Encryption key 1: 0x{header['encryption_key1']:016x}")
            print(f"  Encryption key 2: 0x{header['encryption_key2']:016x}")
            print(f"  Audio data size: {header['audio_data_size']} bytes")
            
            # Read the encrypted audio data
            remaining_size = size - 32
            if header['audio_data_size'] > remaining_size:
                print(f"Warning: Header claims {header['audio_data_size']} bytes but only {remaining_size} available")
                audio_data_size = remaining_size
            else:
                audio_data_size = header['audio_data_size']
            
            encrypted_audio = file_handle.read(audio_data_size)
            if len(encrypted_audio) < audio_data_size:
                print(f"Warning: Could only read {len(encrypted_audio)} of {audio_data_size} bytes")
            
            # Decrypt the audio data
            print("  Decrypting audio data...")
            decrypted_audio = decrypt_audio_data(
                encrypted_audio, 
                header['encryption_key1'], 
                header['encryption_key2'], 
                aes_key
            )
            
            # Save decrypted data with temporary name
            temp_path = output_dir / f"{instrument_name}_decrypted.bin"
            with open(temp_path, 'wb') as df:
                df.write(decrypted_audio)
            
            # Try to detect file format
            final_path = temp_path
            file_type = check_file_type(temp_path)
            
            if file_type:
                print(f"  File type detected: {file_type}")
                
                # Determine extension based on file type
                if 'Ogg data' in file_type or 'OGG' in file_type:
                    final_path = output_dir / f"{instrument_name}.ogg"
                    temp_path.rename(final_path)
                elif 'Opus' in file_type:
                    final_path = output_dir / f"{instrument_name}.opus"
                    temp_path.rename(final_path)
                elif 'MPEG' in file_type or 'MP3' in file_type:
                    final_path = output_dir / f"{instrument_name}.mp3"
                    temp_path.rename(final_path)
                elif 'WAVE' in file_type or 'WAV' in file_type:
                    final_path = output_dir / f"{instrument_name}.wav"
                    temp_path.rename(final_path)
                else:
                    # Keep as .bin if unknown
                    final_path = output_dir / f"{instrument_name}.bin"
                    temp_path.rename(final_path)
            else:
                # Try to detect from magic bytes
                if len(decrypted_audio) >= 4:
                    magic = decrypted_audio[:4]
                    if magic == b'OggS':
                        final_path = output_dir / f"{instrument_name}.ogg"
                        temp_path.rename(final_path)
                        print(f"  Detected OGG format from magic bytes")
                    elif b'OpusHead' in decrypted_audio[:100]:
                        final_path = output_dir / f"{instrument_name}.opus"
                        temp_path.rename(final_path)
                        print(f"  Detected Opus format from magic bytes")
                    else:
                        final_path = output_dir / f"{instrument_name}.bin"
                        temp_path.rename(final_path)
                        print(f"  Unknown format, magic bytes: {magic.hex()}")
                else:
                    final_path = output_dir / f"{instrument_name}.bin"
                    temp_path.rename(final_path)
            
            print(f"  Saved decrypted data: {final_path}")
            
            audio_info.append({
                'index': i,
                'instrument_name': instrument_name,
                'instrument_type': header['instrument_type'],
                'size': len(decrypted_audio),
                'decrypted_path': final_path
            })
            
        except Exception as e:
            print(f"Error processing instrument {i}: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    return audio_info

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

def extract_all(result: Dict[str, Any], output_dir: Path, filepath: str = None):
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
    
    # Extract audio data if filepath provided
    if filepath and result['instrument_offsets'] and result['instrument_sizes']:
        print("\nExtracting audio data...")
        audio_info = extract_audio_data(
            filepath, 
            result['instrument_offsets'], 
            result['instrument_sizes'], 
            output_dir
        )
        result['audio_info'] = audio_info

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
        
        # Calculate absolute offsets for audio data
        # The offsets in the header are relative to the start of audio data section
        current_pos = f.tell()
        
        # Read and decompress chart data
        chart_data_size = additional['chart_data_size']['value']
        compressed_chart = f.read(chart_data_size)
        chart_data = zlib.decompress(compressed_chart, wbits=-15)

        # Read and decompress all images
        for size in image_sizes:
          compressed_image = f.read(size)
          image_data.append(zlib.decompress(compressed_image, wbits=-15))
        
        # Calculate absolute audio offsets
        audio_section_start = f.tell()
        absolute_instrument_offsets = [audio_section_start + offset for offset in instrument_offsets]
        
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
            'instrument_offsets': absolute_instrument_offsets,
            'instrument_sizes': instrument_sizes,
            'chart_data': chart_data,
            'audio_section_start': audio_section_start
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
            extract_all(result, output_dir, str(filepath))
            print(f"\nExtracted to: {output_dir}")
            
            # Print audio extraction summary
            if 'audio_info' in result:
                print(f"\nAudio Extraction Summary:")
                print("-" * 50)
                for audio in result['audio_info']:
                    print(f"  {audio['instrument_name']:12}: {audio['size']:8} bytes")
                print(f"\nTotal instruments extracted: {len(result['audio_info'])}")
            
    except Exception as e:
        print(f"Error processing file: {e}")
        exit(1)
