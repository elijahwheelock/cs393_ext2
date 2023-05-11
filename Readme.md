I've done quite a bit of work on this project, but it's still not where I'd like it to be. What I've done:

 - fix `cd` to file bug
 - modify `ls` to work on large directories
 - implement `cat`, including large directories
 - implement `append` (only for small files)

What I have not done:
 - enough testing
 - implement `touch`
 - implement `mkdir`
 - implement `link <source name> <destination path>` to create hard
   links
 - write tests
 - write more tests
 - implement `rm` (aka unlink) for plain files
 - make `link` robust against ... (what should `link` be robust
   against?)
 - implement `mount <host-file> <dirname>` to mount a local file as an ext2
   filesystem over an empty directory.
 - implement `unmount` to cleanly writes modifications back to the "device"
   (file)
 - implement `import` to get a file from the "host" filesystem into ours
 - any big projects:
	 - make it `#[no_std]` compatible
	 - instead of reading from a big byte-buffer, read from a device into
	   manually managed page-sized buffers
	 - implement a buffer cache
	 - implement `fsck` - identify different inconsistencies and find them
	 - implement a simple line editor (ed?) to create text files in the
	   filesystem
 - any bigger projects:
 	- ext4 support?
 	- integrate with reedos kernel memory allocation
 	- integrate caching with kernel VM

Credits: Dylan McNamee, Reed College CS393 students, @tzlil on the Rust #osdev discord
