differ
=====

#Hash-based remote diff library

This is a simple proof of concept library for remote delta/diff creation similar in function to rdiff and librsync. It does not use a sliding window like librsync but rather fixed size blocks. I needed a library that was cross platform, unencumbered by the GPL and replicated, albeit not as efficiently, the functionality of librsync.

While designing this I found that the algorithmic complexity of librsync wasn't necessary for a couple reasons. If a file is huge (several GB), it is unlikely it will be rewritten so that new data can be inserted in the middle. This is, in my view, a non-problem that librsync solves. If a file is small enough to be rewritten to insert data, uploading it over modern Internet connections without any remote delta trickery (especially using compression) takes relatively little time; time I'm willing to sacrifice for the simplicity of using this library.

There are three functions of note in this library:

##signature(basis_file, sig_file, block_size = 32768)

Takes a basis_file, calculates sha256 hashes for each block_size block and writes out sig_file.

##delta(sig_file, new_file, delta_file)

Takes a sig_file input and new_file input and writes out a delta_file containing instructions on how to rebuild new_file using the delta_file and original basis_file.

##patch(basis_file, delta_file, new_file)

Creates new_file using basis_file and delta_file as inputs.

