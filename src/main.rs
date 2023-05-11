#![feature(int_roundings)]
#![feature(io_error_more)]
#![feature(generators, generator_trait)]

mod structs;
use crate::structs::{
    BlockGroupDescriptor, 
    DirectoryEntry,
    Inode,
    Superblock,
    TypePerm,
};
use core::{
    mem,
    ops::{Generator, GeneratorState},
    pin::Pin,
};
use null_terminated::NulStr;
use rustyline::{DefaultEditor, Result};
use std::{
    alloc::{
        alloc_zeroed,
        Layout,   
    },
    fmt,   
    fs::File,
    io::{Error,
         ErrorKind::*,
         prelude::*,
    },
};
use uuid::Uuid;
use zerocopy::ByteSlice;

#[repr(C)]
#[derive(Debug)]
pub struct Ext2 {
    pub superblock: &'static Superblock,
    pub block_groups: &'static [BlockGroupDescriptor],
    pub blocks: Vec<&'static mut [u8]>,
    pub block_size: usize,
    pub uuid: Uuid,
    pub block_offset: usize, // <- our "device data" actually starts at the block_offset'th block of the device so we have to subtract this number before indexing blocks[]
}

const EXT2_MAGIC: u16 = 0xef53;
const EXT2_START_OF_SUPERBLOCK: usize = 1024;
const EXT2_END_OF_SUPERBLOCK: usize = 2048;

impl Ext2 {
    pub fn new<B: ByteSlice + std::fmt::Debug>(
        device_bytes: B,
        start_addr: usize,
    ) -> Ext2 {
        // https://wiki.osdev.org/Ext2#Superblock
        // parse into Ext2 struct - without copying
        // the superblock goes from bytes 1024 -> 2047
        let header_body_bytes = device_bytes.split_at(EXT2_END_OF_SUPERBLOCK);
        let superblock = unsafe {
            &*(header_body_bytes.0
                                .split_at(EXT2_START_OF_SUPERBLOCK)
                                .1
                                .as_ptr() as *const Superblock)
        };
        assert_eq!(superblock.magic, EXT2_MAGIC);
        // at this point, we strongly suspect these bytes are indeed an ext2 filesystem
        println!("superblock:\n{:?}", superblock);
        println!("size of Inode struct: {}", mem::size_of::<Inode>());

        let block_group_count =
            superblock.blocks_count
                      .div_ceil(superblock.blocks_per_group) as usize;
        let block_size: usize = 1024 << superblock.log_block_size;
        println!(
            "there are {} block groups and block_size = {}",
            block_group_count,
            block_size
        );
        let block_groups_rest_bytes = header_body_bytes.1.split_at(block_size);
        let block_groups = unsafe {
            core::slice::from_raw_parts(
                block_groups_rest_bytes.0.as_ptr() as *const BlockGroupDescriptor,
                block_group_count,
            )
        };
        println!("block group 0: {:?}", block_groups[0]);

        let blocks = unsafe {
            core::slice::from_raw_parts_mut(
                block_groups_rest_bytes.1.as_ptr() as *mut u8,
                // would rather use: device_bytes.as_ptr(),
                superblock.blocks_count as usize * block_size,
            )
        }.chunks_mut(block_size)
         .collect::<Vec<_>>();
        let offset_bytes = (blocks[0].as_ptr() as usize) - start_addr;
        let block_offset = offset_bytes / block_size;
        let uuid = Uuid::from_bytes(superblock.fs_id);
        Ext2 {
            superblock,
            block_groups,
            blocks,
            block_size,
            uuid,
            block_offset,
        }
    }

    pub fn get_blocks_gen(&self, inode_num: usize)
    -> GeneratorIteratorAdapter<impl Generator<Yield = *const u8, Return = ()> + '_>
    {
        GeneratorIteratorAdapter::new(
            move || {
                let inode = self.get_inode(inode_num);
                let mut block_num = 0;
                let n_ptrs_in_block = (self.block_size / mem::size_of::<u32>()) as isize;
                while block_num < 12 {
                    // direct pointers
                    // println!("{:?}", inode);
                    if inode.direct_pointer[block_num as usize] == 0 {
                        return;
                    }
                    let block = 
                        self.blocks[inode.direct_pointer[block_num as usize] as usize
                                    - self.block_offset
                                   ].as_ptr() as *const u8;
                    if block == std::ptr::null() {
                        return;
                    }
                    yield block;
                    block_num += 1;
                }

                // indirect pointers
                let indirect_pointer = self.blocks[inode.indirect_pointer as usize - self.block_offset].as_ptr();
                if indirect_pointer == std::ptr::null() {
                    return;
                }
                for direct_block in 0..n_ptrs_in_block {
                    let block = unsafe {
                        if *indirect_pointer.offset(direct_block) == 0 {
                            return;
                        }
                        self.blocks[*indirect_pointer.offset(direct_block) as usize 
                                    - self.block_offset
                                   ].as_ptr() as *const u8
                    };
                    if block == std::ptr::null() {
                        return;
                    }
                    yield block;
                    block_num += 1;
                }

                // doubly indirect pointers
                let doubly_indirect = self.blocks[inode.doubly_indirect as usize - self.block_offset].as_ptr();
                if doubly_indirect == std::ptr::null() {
                    return;
                }
                for ind_block in 0..n_ptrs_in_block {
                    let indirect_pointer = unsafe {
                        if *doubly_indirect.offset(ind_block) == 0 {
                            return;
                        }
                        self.blocks[*doubly_indirect.offset(ind_block) as usize - self.block_offset].as_ptr()
                    };
                    if indirect_pointer == std::ptr::null() {
                        return;
                    }
                    for direct_block in 0..n_ptrs_in_block {
                        let block = unsafe{
                            self.blocks[*indirect_pointer.offset(direct_block) as usize 
                                        - self.block_offset
                                        ].as_ptr() as *const u8
                        };
                        if block == std::ptr::null() {
                            return;
                        }
                        yield block;
                        block_num += 1;
                    }
                }

                // triply indirect pointers
                let triply_indirect = self.blocks[inode.triply_indirect as usize - self.block_offset].as_ptr();
                if triply_indirect == std::ptr::null() {
                    return;
                }
                for double_block in 0..n_ptrs_in_block {
                    let doubly_indirect = unsafe {
                        if *triply_indirect.offset(double_block) == 0 {
                            return;
                        }
                        self.blocks[*triply_indirect.offset(double_block) as usize 
                                    - self.block_offset
                                ].as_ptr()
                    };
                    if doubly_indirect == std::ptr::null() {
                        return;
                    }
                    for ind_block in 0..n_ptrs_in_block {
                        let indirect_pointer = unsafe {
                            self.blocks[*doubly_indirect.offset(ind_block) as usize - self.block_offset].as_ptr()
                        };
                        if indirect_pointer == std::ptr::null() {
                            return;
                        }
                        for direct_block in 0..n_ptrs_in_block {
                            let block = unsafe {
                                self.blocks[*indirect_pointer.offset(direct_block) as usize 
                                            - self.block_offset
                                        ].as_ptr() as *const u8
                            };
                            if block == std::ptr::null() {
                                return;
                            }
                            yield block;
                            block_num += 1;
                        }
                    }
                }
            }
        )
    }

    pub fn get_child_by_name(&self, inode: usize, name: &String)
    -> std::io::Result<usize>
    {
        if self.is_directory(inode) {
            let files = self.read_dir_inode(inode)?;
            for file in files {
                if file.1.to_string().eq(name) {
                    return Ok(file.0);
                }
            }
            return Err(NotFound.into());
        }
        else {
            return Err(Error::new(NotADirectory, format!("not a directory: {}", name)));
        }
    }

    pub fn get_child_by_path(&self, inode: usize, path: &str)
    -> std::io::Result<usize>
    {
        let path = path.to_string();
        let mut current_inode = inode;
        let split = path.split('/').collect::<Vec<_>>();
        let (target, filenames) = match split.split_last() {
            Some((target, filenames)) => (target, filenames),
            None => {
                return Err(Error::new(InvalidInput, format!("invalid input: {}", path)));
            }
        };
        for filename in filenames {
            current_inode =
                self.get_child_by_name(current_inode, &filename.to_string())?;
        }
        self.get_child_by_name(current_inode, &target.to_string())
    }

    // given a (1-indexed) inode number, return that #'s inode structure
    pub fn get_inode(&self, inode: usize) -> &mut Inode {
        let group: usize = (inode - 1) / self.superblock.inodes_per_group as usize;
        let index: usize = (inode - 1) % self.superblock.inodes_per_group as usize;
        // println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let inode_table_block = (self.block_groups[group].inode_table_block) as usize - self.block_offset;
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let inode_table = unsafe {
            core::slice::from_raw_parts_mut(
                self.blocks[inode_table_block].as_ptr() as *mut Inode,
                self.superblock.inodes_per_group as usize,
            )
        };
        // probably want a Vec of BlockGroups in our Ext structure
        // so we don't have to slice each time,
        // but this works for now.
        // println!("{:?}", inode_table);
        &mut inode_table[index]
    }

    pub fn is_directory(&self, inode: usize) -> bool {
        self.get_inode(inode).type_perm.contains(TypePerm::DIRECTORY)
    }

    pub fn read_dir_inode(&self, inode: usize)
    -> std::io::Result<Vec<(usize, &NulStr)>>
    {
        let mut ret = Vec::new();
        // println!("in read_dir_inode, #{} : {:?}", inode, root);
        // println!("following direct pointer to data block: {}", root.direct_pointer[0]);
        let blocks = self.get_blocks_gen(inode);
        for block in blocks {
            let mut byte_offset: isize = 0;
            while byte_offset < (self.block_size as isize) {
                let directory = unsafe { &*(block.offset(byte_offset) as *const DirectoryEntry) };
                // println!("{:?}", directory);
                if directory.inode == 0 {
                    continue;
                }
                byte_offset += directory.entry_size as isize;
                ret.push((directory.inode as usize, &directory.name));
            }
        }
        Ok(ret)
    }
}

impl Inode {
    pub fn size(&self) -> usize {
        ((self.size_high as usize) << 31) + self.size_low as usize
    }
}

impl fmt::Debug for Inode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.size_low == 0 && self.size_high == 0 {
            f.debug_struct("").finish()
        } else {
            f.debug_struct("Inode")
             .field("type_perm", &self.type_perm)
             .field("size_low", &self.size_low)
             .field("size_high", &self.size_low)
             .field("size", &self.size())
             .field("direct_pointers", &self.direct_pointer)
             .field("indirect_pointer", &self.indirect_pointer)
             .finish()
        }
    }
}

// the following copied from 
// https://stackoverflow.com/questions/16421033/lazy-sequence-generation-in-rust#30279122
pub struct GeneratorIteratorAdapter<G>(Pin<Box<G>>);

impl<G> GeneratorIteratorAdapter<G>
where
    G: Generator<Return = ()>,
{
    fn new(gen: G) -> Self {
        Self(Box::pin(gen))
    }
}

impl<G> Iterator for GeneratorIteratorAdapter<G>
where
    G: Generator<Return = ()>,
{
    type Item = G::Yield;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.as_mut().resume(()) {
            GeneratorState::Yielded(x) => Some(x),
            GeneratorState::Complete(_) => None,
        }
    }
}

fn main() -> Result<()> {
    //let mut disk = include_bytes!("../myfs.ext2");
    let mut file = File::open("../myfs.ext2").unwrap();
    let mut v = Vec::new();
    file.read_to_end(&mut v);
    let buf = v.as_mut_slice();
    let start_addr: usize = buf.as_ptr() as usize;
    let mut ext2 = Ext2::new(&buf[..], start_addr);
    let mut current_inode: usize = 2;
    let mut rl = DefaultEditor::new()?;
    loop {
        // fetch the children of the current working directory
        let _dirs = match ext2.read_dir_inode(current_inode) {
            Ok(dir_listing) => dir_listing,
            Err(_) => {
                println!("unable to read cwd");
                continue;
            }
        };
        let buffer = rl.readline(":> ");

        if let Ok(line) = buffer {
            let elts: Vec<&str> = line.split(' ').collect();
            let (cmd, args) = match elts.split_first() {
                Some((cmd, args)) => (cmd, args),
                None              => continue,
            };

            if cmd == &"ls" {
                // `ls` prints our cwd's children
                let inode_num =
                    if args.len() >= 1 {
                        match ext2.get_child_by_path(current_inode, args[0]) {
                            Ok(inode) => inode,
                            Err(e) => {
                                println!("{:?}", e);
                                continue;
                            }
                        }
                    }
                    else {
                        current_inode
                    };
                if ext2.is_directory(inode_num) {
                    let dirs = match ext2.read_dir_inode(inode_num) {
                        Ok(dir_listing) => dir_listing,
                        Err(e) => {
                            println!("unable to read cwd");
                            println!("{:?}", e);
                            continue;
                        }
                    };
                    for dir in &dirs {
                        print!("{}\t", dir.1);
                    }
                    println!();
                }
                else {
                    println!("not a directory: {}", args[0]);
                }
            }

            else if cmd == &"cd" {
                // `cd` with no arguments goes back to root
                // `cd path` moves cwd to that path
                if args.len() == 0 {
                    current_inode = 2;
                } else {
                    let inode_num = match ext2.get_child_by_path(current_inode, args[0]) {
                        Ok(inode) => inode,
                        Err(e) => {
                            println!("{:?}", e);
                            continue;
                        }
                    };
                    if ext2.is_directory(inode_num) {
                        current_inode = inode_num;
                    }
                    else {
                        println!("not a directory: {}", args[0]);
                    }
                }
            }

            else if line.starts_with("mkdir") {
                // `mkdir childname`
                // create a directory with the given name, add a link to cwd
                // consider supporting `-p path/to_file` to create a path of directories
                println!("mkdir not yet implemented");
             }

            else if cmd == &"cat" {
                // `cat filename`
                // print the contents of filename to stdout
                // if it's a directory, print a nice error
                let inode_num = match ext2.get_child_by_path(current_inode, args[0]) {
                    Ok(inode_num) => inode_num,
                    Err(e) => {
                        println!("{:?}", e);
                        continue;
                    }
                };
                if !ext2.is_directory(inode_num) {
                    unsafe {
                        let blocks_gen = ext2.get_blocks_gen(inode_num);
                        for block in blocks_gen {
                            for i in 0..ext2.block_size as isize {
                                print!("{}", *block.offset(i) as char);
                            }
                        }
                    };
                }
                else {
                    println!("is a directory: {}", args[0]);
                }
            }

            else if cmd == &"append" {
                let inode_num = match ext2.get_child_by_path(current_inode, args[0]) {
                    Ok(inode) => inode,
                    Err(e) => {
                        println!("{:?}", e);
                        continue;
                    }
                };
                let s = args[1..].join("");
                let b = s.as_bytes();
                b.push(10);
                let inode: &mut Inode = ext2.get_inode(inode_num);
                let size = inode.size();
                let n_ptrs_in_block = ext2.block_size / mem::size_of::<u32>();
                let (block_num, mut byte_offset) = (size / n_ptrs_in_block, size % n_ptrs_in_block);
                let mut current_byte = 0;
                while current_byte < b.len() && block_num < 12 {
                    if inode.direct_pointer[block_num] == 0 {
                        unsafe {
                            let p = alloc_zeroed(Layout::array::<u8>(ext2.block_size).unwrap());
                            let slice = core::slice::from_raw_parts_mut(p, ext2.block_size);
                            inode.direct_pointer[block_num] = ext2.blocks.len() as u32;
                            ext2.blocks.push(slice);
                            // TODO possibly need to make a new block group, but the given definition for the Ext2
                            //      struct doesn't allow adding block groups, so I'm assuming that's outside the scope
                            //      of this project.
                        }
                    }
                    else {
                        let tmp = inode.direct_pointer[block_num] as usize;
                        let current_block = &mut ext2.blocks[tmp - ext2.block_offset];
                        if byte_offset > 0 {
                            byte_offset -= 1
                        }
                        while current_byte < b.len() && byte_offset < ext2.block_size {
                            current_block[byte_offset] = b[current_byte];
                            current_byte += 1;
                            byte_offset += 1;
                        }
                        block_num += 1;
                    }
                }
            }

            else if line.starts_with("rm") {
                // `rm target`
                // unlink a file or empty directory
                println!("rm not yet implemented");
            }

            else if line.starts_with("mount") {
                // `mount host_filename mountpoint`
                // mount an ext2 filesystem over an existing empty directory
                println!("mount not yet implemented");
            }

            else if line.starts_with("link") {
                // `link arg_1 arg_2`
                // create a hard link from arg_1 to arg_2
                // consider what to do if arg2 does- or does-not end in "/"
                // and/or if arg2 is an existing directory name
                println!("link not yet implemented");
            }

            else if line.starts_with("quit") || line.starts_with("exit") {
                break;
            }

        } else {
            println!("bye!");
            break;
        }
    }
    Ok(())
}
