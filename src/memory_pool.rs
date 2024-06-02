//! Efficient memory pool that can be used to allocate and deallocate memory in a thread-safe manner.
//! Allocated data is a `&mut [u8]` that can be used to read and write data.
//! 
//! # Note
//! 
//! This memory pool is not meant to be used for general purpose memory allocation.
//! 
//! As the pool is a Rust `Vec<u8>`, it is not necessary to deallocate memory manually to avoid memory leaks.
//! However, it is important to deallocate memory to allow the pool to reuse it.
use std::slice;
use std::sync::Mutex;

#[derive(Debug)]
struct Block {
    offset: usize,
    size: usize,
}

#[derive(Debug)]
pub struct InnerMemoryPool {
    pool: Vec<u8>,
    free_blocks: Vec<Block>,
}

#[derive(Debug)]
pub struct MemoryPool {
    inner: Mutex<InnerMemoryPool>,
}

impl MemoryPool {
    pub fn new(capacity: usize) -> Self {
        let inner_mem_pool = InnerMemoryPool {
            pool: Vec::<u8>::with_capacity(capacity),
            free_blocks: vec![Block { offset: 0, size: capacity }],
        };
        MemoryPool {
            inner: Mutex::new(inner_mem_pool),
        }
    }

    pub fn allocate(&self, size: usize) -> Result<&mut [u8], &'static str> {
        let mut allocator = self.inner.lock().unwrap();

        let free_blocks = &mut allocator.free_blocks;
        
        if let Some(index) = free_blocks.iter().position(|block| block.size >= size) {
            let offset = free_blocks[index].offset;
            free_blocks[index].offset += size;
            free_blocks[index].size -= size;
            if free_blocks[index].size == 0 {
                free_blocks.remove(index);
            }
            let ptr = unsafe { allocator.pool.as_mut_ptr().add(offset) };
            return Ok(unsafe { slice::from_raw_parts_mut(ptr, size) });
        }

        Err("Insufficient capacity")
    }

    pub fn allocate_blocking(&self, size: usize) -> &mut [u8] {
        loop {
            match self.allocate(size) {
                Ok(ptr) => return ptr,
                Err(_) => continue,
            }
        }
    }

    pub fn deallocate(&self, ptr: &mut [u8]) {
        let mut allocator = self.inner.lock().unwrap();
        let pool_size = allocator.pool.as_ptr() as usize;
        let free_blocks = &mut allocator.free_blocks;
        let size = ptr.len();
        let ptr = ptr.as_mut_ptr();
        let offset = (ptr as usize) - (pool_size);

        let index = free_blocks.iter().position(|block| block.offset > offset).unwrap_or(free_blocks.len());

        // Insert by merging with previous and next blocks if possible
        let mut inserted_after = false;
        let mut inserted_before = false;
        if free_blocks.len() > 0 && index < free_blocks.len() && free_blocks[index].offset == offset + size {
            inserted_after = true;
            free_blocks[index].offset = offset;
            free_blocks[index].size += size;
        }
        if index > 0 && free_blocks[index-1].offset + free_blocks[index-1].size == offset {
            inserted_before = true;
            free_blocks[index-1].size += match inserted_after{
                true => {
                    free_blocks[index].size
                },
                false => size,
            };
            if inserted_after {
                free_blocks.remove(index);
            }
        }
        if !inserted_after && !inserted_before {
            free_blocks.insert(index, Block { offset, size });
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_basic_memory_pool() {
        let memory_pool = MemoryPool::new(1024);
        let ptr = memory_pool.allocate(512).unwrap();
        let ptr2 = memory_pool.allocate(512).unwrap();
        assert_eq!(ptr.as_mut_ptr() as usize + 512, ptr2.as_mut_ptr() as usize);
        memory_pool.deallocate(ptr);
        memory_pool.deallocate(ptr2);
    }

    #[test]
    #[should_panic]
    fn test_memory_pool_panic() {
        let memory_pool = MemoryPool::new(1024);
        let ptr = memory_pool.allocate(1024).unwrap();
        let ptr2 = memory_pool.allocate(1).unwrap();

        memory_pool.deallocate(ptr);
        memory_pool.deallocate(ptr2);
    }

    #[test]
    fn test_reallocate_small_part() {
        let memory_pool = MemoryPool::new(1024);
        let ptr = memory_pool.allocate(512).unwrap();
        let ptr2 = memory_pool.allocate(512).unwrap();
        assert_eq!(ptr.as_mut_ptr() as usize + 512, ptr2.as_mut_ptr() as usize);
        memory_pool.deallocate(ptr);
        let ptr3 = memory_pool.allocate(512).unwrap();
        assert_eq!(ptr.as_mut_ptr() as usize, ptr3.as_mut_ptr() as usize);
        memory_pool.deallocate(ptr2);
        memory_pool.deallocate(ptr3);
    }

    #[test]
    fn test_merge_blocks() {
        let memory_pool = MemoryPool::new(1024);
        let mut ptrs = vec![
            memory_pool.allocate(256).unwrap(),
            memory_pool.allocate(256).unwrap(),
            memory_pool.allocate(256).unwrap(),
            memory_pool.allocate(256).unwrap(),
        ];
        for i in 0..4 {
            memory_pool.deallocate(ptrs[i]);
        }
        let ptr1 = memory_pool.allocate(512).unwrap();
        let ptr2 = memory_pool.allocate(512).unwrap();
        assert_eq!(ptr1.as_mut_ptr() as usize + 512, ptr2.as_mut_ptr() as usize);
        memory_pool.deallocate(ptr1);
        memory_pool.deallocate(ptr2);
    }

    #[test]
    fn test_block_resize() {
        let memory_pool = MemoryPool::new(1024);
        let ptr = memory_pool.allocate(512).unwrap();
        let ptr2 = memory_pool.allocate(512).unwrap();
        assert_eq!(ptr.as_mut_ptr() as usize + 512, ptr2.as_mut_ptr() as usize);
        memory_pool.deallocate(ptr);
        let ptr3 = memory_pool.allocate(512).unwrap();
        assert_eq!(ptr.as_mut_ptr() as usize, ptr3.as_mut_ptr() as usize);
        memory_pool.deallocate(ptr2);
        memory_pool.deallocate(ptr3);
    }

    #[test]
    fn test_overlapping() {
        let memory_pool = MemoryPool::new(1024);
        let ptr = memory_pool.allocate(512).unwrap();
        let ptr2 = memory_pool.allocate(512).unwrap();
        for i in 0..512 {
            ptr[i] = 1u8;
            ptr2[i] = 2u8;
        }
        for i in 0..512 {
            assert_eq!(ptr[i], 1u8);
            assert_eq!(ptr2[i], 2u8);
        }
        memory_pool.deallocate(ptr);
        memory_pool.deallocate(ptr2);
    }

    #[test]
    fn test_sync_in_threads() {
        let memory_pool = Arc::new(MemoryPool::new(1048576));
        let memory_pool2 = memory_pool.clone();
        let memory_pool3 = memory_pool.clone();
        let handle = std::thread::spawn(move || {
            let ptr = memory_pool.allocate(524288).unwrap();
            for i in 0..524288 {
                ptr[i] = 1u8;
            }
            for i in 0..524288 {
                assert_eq!(ptr[i], 1u8);
            }
            memory_pool.deallocate(ptr)
        });
        let handle2 = std::thread::spawn(move || {
            let ptr2 = memory_pool2.allocate(524288).unwrap();
            for i in 0..524288 {
                ptr2[i] = 2u8;
            }
            for i in 0..524288 {
                assert_eq!(ptr2[i], 2u8);
            }
            memory_pool2.deallocate(ptr2)
        });
        handle.join().unwrap();
        let ptr3 = memory_pool3.allocate(524288).unwrap();
        memory_pool3.deallocate(ptr3);
        handle2.join().unwrap();
    }

    #[test]
    fn test_lots_of_allocations() {
        let memory_pool = MemoryPool::new(1048576);
        let mut ptrs = Vec::new();
        for _ in 0..1024 {
            let ptr = memory_pool.allocate(1024).unwrap();
            for i in 0..1024 {
                ptr[i] = 1u8;
            }
            ptrs.push(ptr);
        }
        for ptr in ptrs {
            memory_pool.deallocate(ptr);
        }
        let ptr = memory_pool.allocate(1048576).unwrap();
        // Note: This should not be done in practice
        // As allocated memory content is undefined
        for i in 0..1048576 {
            assert_eq!(ptr[i], 1u8);
        }
        memory_pool.deallocate(ptr);
    }

    #[test]
    fn test_lots_of_alloc_and_threads() {
        const NB_ALLOCS: usize = 1024*8;
        const ALLOC_SIZE: usize = 16;
        let memory_pool = Arc::new(MemoryPool::new(NB_ALLOCS * ALLOC_SIZE));
        let memory_pool2 = memory_pool.clone();
        let mut handles = Vec::new();
        for _ in 0..NB_ALLOCS {
            let memory_pool = memory_pool.clone();
            let handle = std::thread::spawn(move || {
                let ptr = memory_pool.allocate(ALLOC_SIZE).unwrap();
                for i in 0..ALLOC_SIZE {
                    ptr[i] = 1u8;
                }
                {
                    let mp = memory_pool.inner.lock().unwrap();
                    println!("{:?}", ptr.as_mut_ptr() as usize - mp.pool.as_ptr() as usize);
                    println!("{:?}", ptr.len());
                    println!("{:?}", mp.free_blocks);
                }
                memory_pool.deallocate(ptr);
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.join().unwrap();
        }
        println!("{:?}", memory_pool.inner.lock().unwrap().free_blocks);
        let handle = std::thread::spawn(move || {
            let ptr = memory_pool2.allocate(NB_ALLOCS*ALLOC_SIZE).unwrap();
            memory_pool2.deallocate(ptr);
        });
        handle.join().unwrap();
    }
}
