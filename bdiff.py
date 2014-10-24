#!/usr/bin/env python

from hashlib import sha256, md5
import struct

__VERSION = 2

def __read_blocks(file_object, chunk_size):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        # If the OS returns a partial block and is not EOF
        # keep trying for the rest of the block
        block_tries = 0
        while len(data) < chunk_size:
            more_data = file_object.read(chunk_size - len(data))
            if not more_data:
                break
            data = data + more_data
            
            # Retry 10 times and raise exception on failure as this
            # library relies on consistently sized blocks.
            block_tries += 1
            if block_tries > 10:
                raise Exception("Could not get proper size block")
        yield data

def signature(basis_file, sig_file, block_size = 4096):
    """Generate a signature from a basis file
    
    Arguments:
    basis_file: The original file that needs to be updated
    sig_file: File object to output the signature
    block_size: (Optional) Number of bytes per block. Fixed at this value for
    the rest of the process (delta and patch)
    """
    # Write the identifier string, file type and version number
    sig_file.write('bdif')
    sig_file.write('sig')
    sig_file.write(struct.pack('i', __VERSION))
    
    # Next four bytes of the file is the block size    
    sig_file.write(struct.pack('i', block_size))
    
    # Calculate the hash of each block and write it (32 bytes) to sig_file.
    for block in __read_blocks(basis_file, block_size):
        h = md5(block)
        sig_file.write(h.digest())

def delta(sig_file, new_file, delta_file):
    """Generate a patch file using a signature and new file
    
    Arguments:
    sig_file: File object for the signature file
    new_file: The updated file we are trying to replicate
    delta_file: File object to which the patch instruction will be written
    """
    # Verify the file is for us
    if not sig_file.read(7) == 'bdifsig':
        raise Exception('Not a bdiff sig file')
    
    # Get the version number
    version_bytes = sig_file.read(4)
    version = int(struct.unpack('i', version_bytes)[0])
    
    if version == 2:
        # Get block_size from sig_file
        block_size_bytes = sig_file.read(4)
        block_size = int(struct.unpack('i', block_size_bytes)[0])
        
        # Write the identifier string, file type and version number
        delta_file.write('bdif')
        delta_file.write('dlt')
        delta_file.write(struct.pack('i', __VERSION))
        
        # Save the block size to the delta file
        delta_file.write(block_size_bytes)    
        
        # Read the signatures into memory
        signatures = {}
        block_number = 0
        for block in __read_blocks(sig_file, 16):
            signatures[block] = block_number
            block_number += 1
        
        # Read the new_file calculating block hashes and comparing them to
        # the list from sig_file. Also calculate a whole file hash for error
        # checking.
        file_h = sha256()
        for block in __read_blocks(new_file, block_size):
            h = md5(block)
            file_h.update(block)
            block_hash = h.digest()
            if block_hash in signatures:
                # Found the block in the basis_file so write an instruction
                # to copy that block from the basis_file
                delta_file.write('C')
                delta_file.write(struct.pack('i', signatures[block_hash]))
            elif len(block) == block_size:
                # Block not found in basis_file so write an instruction
                # to get the block from delta_file and include the block data
                delta_file.write('D')
                delta_file.write(block)
            else:
                # Block not found and the block we got is shorter than block_size
                # so write a different instruction that includes the block length
                delta_file.write('E')
                delta_file.write(struct.pack('i', len(block)))
                delta_file.write(block)
        
        # Write the complete file hash to the delta file
        delta_file.write('H')
        delta_file.write(file_h.digest())
    else:
        raise Exception("Unknown signature file version")
            
def patch(basis_file, delta_file, new_file):
    """Patch basis_file using the instructions in delta_file
    
    Arguments:
    basis_file: The original file from which the signature was created
    delta_file: The file object containing the patch instructions
    new_file: The final patched file object
    """
    # Verify the file is for us
    if not delta_file.read(7) == 'bdifdlt':
        raise Exception('Not a bdiff delta file')
    
    # Get the version number
    version_bytes = delta_file.read(4)
    version = int(struct.unpack('i', version_bytes)[0])
    
    if version == 2:
        # Get block size from delta_file
        block_size = int(struct.unpack('i', delta_file.read(4))[0])
        
        file_h = sha256()
        file_h_target = ''
        
        # Read the instructions from the delta_file
        while True:
            mode = delta_file.read(1)
            if not mode:
                break
            if mode == 'C':
                # Copy mode. Get the data from basis_file
                block_number = int(struct.unpack('i', delta_file.read(4))[0])
                basis_file.seek(block_number * block_size)
                data = basis_file.read(block_size)
            elif mode == 'D':
                # Delta mode. Get the data from the delta file
                data = delta_file.read(block_size)
            elif mode == 'E':
                # Delta mode but with a short block (EOF)
                delta_bytes = int(struct.unpack('i', delta_file.read(4))[0])
                data = delta_file.read(delta_bytes)
            elif mode == 'H':
                # Found the complete file hash. new_file should match this.
                file_h_target = delta_file.read(32)
                break
            else:
                raise Exception("Incorrectly formatted delta file")
            
            new_file.write(data)
            file_h.update(data)
            
        if not file_h.digest() == file_h_target:
            raise Exception("Hash mismatch in new file")
    else:
        raise Exception("Unknown delta file version")


# This library isn't really meant to be used from the command line except
# for some rudimentary testing. Thus, the below code has very little error
# checking or polish.
if __name__ == '__main__':
    from sys import argv
    
    if argv[1] == "sig":
        # Command line params:
        #     basis_file sig_file
        try:
            with open(argv[2],'rb') as basis_file:
                with open(argv[3],'wb') as sig_file:
                    signature(basis_file, sig_file)
        except IOError:
            print "signature problem"

    elif argv[1] == "delta":
        # Command line params:
        #     sig_file new_file delta
        try:
            with open(argv[2],'rb') as sig_file:
                with open(argv[3],'rb') as new_file:
                    with open(argv[4],'wb') as delta_file:
                        delta(sig_file, new_file, delta_file)
        except IOError:
            print "delta problem"

    elif argv[1] == "patch":
        # Command line params:
        #     basis_file delta_file new_file
        try:
            with open(argv[2],'rb') as basis_file:
                with open(argv[3],'rb') as delta_file:
                    with open(argv[4],'wb') as new_file:
                        patch(basis_file, delta_file, new_file)
        except IOError:
            print "patch problem"
            
    else:
        print "Must specific one of sig, delta or patch"
