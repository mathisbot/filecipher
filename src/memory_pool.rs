//! Efficient memory pool that can be used to allocate and deallocate memory in a thread-safe manner.
//! Allocated data is a `&mut [T]` that can be used to read and write data.
//! 
//! As the pool is a Rust `Vec<T>`, it is not necessary to deallocate memory manually to avoid memory leaks.
//! However, it is important to deallocate memory to allow the pool to reuse it.
use std::slice;
use parking_lot::Mutex;

#[derive(Debug)]
pub struct InsufficientCapacityError;

#[derive(Debug)]
struct Block {
    offset: usize,
    size: usize,
}

#[derive(Debug)]
pub struct MemoryPool<T> {
    _pool: Vec<T>, // Never explicitly used
    pool_ptr: usize,
    free_blocks: Mutex<Vec<Block>>,
}

impl<T> MemoryPool<T> {
    pub fn new(capacity: usize) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        unsafe { pool.set_len(capacity) };
        let pool_ptr = pool.as_ptr() as usize;
        let free_blocks = Mutex::new(vec![Block { offset: 0, size: capacity }]);
        Self { _pool: pool, pool_ptr, free_blocks }
    }

    pub fn allocate(&self, size: usize) -> Result<&mut [T], InsufficientCapacityError> {
        let mut free_blocks = self.free_blocks.lock();
        
        if let Some(index) = free_blocks.iter().position(|block| block.size >= size) {
            let offset = free_blocks[index].offset;
            free_blocks[index].offset += size;
            free_blocks[index].size -= size;
            if free_blocks[index].size == 0 {
                free_blocks.remove(index);
            }
            let ptr = (self.pool_ptr + offset) as *mut T;
            return Ok(unsafe { slice::from_raw_parts_mut(ptr, size) });
        }

        Err(InsufficientCapacityError)
    }

    pub fn allocate_blocking(&self, size: usize) -> &mut [T] {
        loop {
            match self.allocate(size) {
                Ok(ptr) => return ptr,
                // Memory pool is full, wait for deallocation
                Err(InsufficientCapacityError) => std::thread::yield_now(),
            }
        }
    }

    pub fn deallocate(&self, ptr: &mut [T]) {
        let size = ptr.len();
        let ptr = ptr.as_mut_ptr();
        let offset = ptr as usize - self.pool_ptr;
        
        let mut free_blocks = self.free_blocks.lock();
        let index = free_blocks.iter().position(|block| block.offset > offset).unwrap_or(free_blocks.len());

        if index > 0 && free_blocks[index - 1].offset + free_blocks[index - 1].size == offset {
            free_blocks[index - 1].size += size;
            if index < free_blocks.len() && offset + size == free_blocks[index].offset {
                free_blocks[index - 1].size += free_blocks[index].size;
                free_blocks.remove(index);
            }
        } else if index < free_blocks.len() && offset + size == free_blocks[index].offset {
            free_blocks[index].offset = offset;
            free_blocks[index].size += size;
        } else {
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
        let memory_pool = MemoryPool::<u8>::new(1024);
        let ptr = memory_pool.allocate(512).unwrap();
        let ptr2 = memory_pool.allocate(512).unwrap();
        assert_eq!(ptr.as_ptr() as usize + 512, ptr2.as_ptr() as usize);
        memory_pool.deallocate(ptr);
        memory_pool.deallocate(ptr2);
    }

    #[test]
    #[should_panic]
    fn test_memory_pool_panic() {
        let memory_pool = MemoryPool::<u8>::new(1024);
        let ptr = memory_pool.allocate(1024).unwrap();
        let ptr2 = memory_pool.allocate(1).unwrap();

        memory_pool.deallocate(ptr);
        memory_pool.deallocate(ptr2);
    }

    #[test]
    fn test_reallocate_small_part() {
        let memory_pool = MemoryPool::<u8>::new(1024);
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
        let memory_pool = MemoryPool::<u8>::new(1024);
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
        let memory_pool = MemoryPool::<u8>::new(1024);
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
        let memory_pool = MemoryPool::<u8>::new(1024);
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
        let memory_pool = Arc::new(MemoryPool::<u8>::new(1048576));
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
        let memory_pool = MemoryPool::<u8>::new(1048576);
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
        const NB_ALLOCS: usize = 1024*32;
        const ALLOC_SIZE: usize = 8;
        let memory_pool = Arc::new(MemoryPool::<u8>::new(NB_ALLOCS * ALLOC_SIZE));
        let memory_pool2 = memory_pool.clone();
        let mut handles = Vec::new();
        for _ in 0..NB_ALLOCS {
            let memory_pool = memory_pool.clone();
            let handle = std::thread::spawn(move || {
                let ptr = memory_pool.allocate(ALLOC_SIZE).unwrap();
                for i in 0..ALLOC_SIZE {
                    ptr[i] = 1u8;
                }
                memory_pool.deallocate(ptr);
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let handle = std::thread::spawn(move || {
            let ptr = memory_pool2.allocate(NB_ALLOCS*ALLOC_SIZE).unwrap();
            memory_pool2.deallocate(ptr);
        });
        handle.join().unwrap();
    }
}
