//! Weak AVL (WAVL) Tree implementation for HuesOS Task Scheduler.
//! Sorted by (vruntime, task_id) to ensure uniqueness of keys.

use core::cmp::Ordering;

pub struct WavlTree {
    root: *mut WavlNode,
}

pub struct WavlNode {
    pub vruntime: u64,
    pub task_id: u64,
    pub rank: i32,
    pub left: *mut WavlNode,
    pub right: *mut WavlNode,
    pub parent: *mut WavlNode,
}

impl WavlNode {
    fn new(vruntime: u64, task_id: u64) -> *mut Self {
        let node = alloc::boxed::Box::new(Self {
            vruntime,
            task_id,
            rank: 0,
            left: core::ptr::null_mut(),
            right: core::ptr::null_mut(),
            parent: core::ptr::null_mut(),
        });
        alloc::boxed::Box::into_raw(node)
    }
}

impl WavlTree {
    pub const fn new() -> Self {
        Self {
            root: core::ptr::null_mut(),
        }
    }

    fn compare(v1: u64, id1: u64, v2: u64, id2: u64) -> Ordering {
        if v1 != v2 {
            v1.cmp(&v2)
        } else {
            id1.cmp(&id2)
        }
    }

    pub fn insert(&mut self, vruntime: u64, task_id: u64) {
        let new_node = WavlNode::new(vruntime, task_id);
        if self.root.is_null() {
            self.root = new_node;
            return;
        }

        let mut curr = self.root;
        let mut parent = core::ptr::null_mut();
        let mut ord = Ordering::Equal;

        while !curr.is_null() {
            parent = curr;
            unsafe {
                ord = Self::compare(vruntime, task_id, (*curr).vruntime, (*curr).task_id);
                curr = match ord {
                    Ordering::Less => (*curr).left,
                    _ => (*curr).right,
                };
            }
        }

        unsafe {
            (*new_node).parent = parent;
            match ord {
                Ordering::Less => (*parent).left = new_node,
                _ => (*parent).right = new_node,
            }
        }

        // Rebalance
        self.insert_rebalance(new_node);
    }

    fn get_rank(&self, node: *mut WavlNode) -> i32 {
        if node.is_null() {
            -1
        } else {
            unsafe { (*node).rank }
        }
    }

    fn rotate_left(&mut self, x: *mut WavlNode) {
        unsafe {
            let y = (*x).right;
            (*x).right = (*y).left;
            if !(*y).left.is_null() {
                (*(*y).left).parent = x;
            }
            (*y).parent = (*x).parent;
            if (*x).parent.is_null() {
                self.root = y;
            } else if x == (*(*x).parent).left {
                (*(*x).parent).left = y;
            } else {
                (*(*x).parent).right = y;
            }
            (*y).left = x;
            (*x).parent = y;
        }
    }

    fn rotate_right(&mut self, x: *mut WavlNode) {
        unsafe {
            let y = (*x).left;
            (*x).left = (*y).right;
            if !(*y).right.is_null() {
                (*(*y).right).parent = x;
            }
            (*y).parent = (*x).parent;
            if (*x).parent.is_null() {
                self.root = y;
            } else if x == (*(*x).parent).left {
                (*(*x).parent).left = y;
            } else {
                (*(*x).parent).right = y;
            }
            (*y).right = x;
            (*x).parent = y;
        }
    }

    fn insert_rebalance(&mut self, mut x: *mut WavlNode) {
        unsafe {
            while !(*x).parent.is_null() {
                let p = (*x).parent;
                let rank_p = (*p).rank;
                let rank_x = (*x).rank;

                // Rank difference is 0 -> needs promotion or rotation
                if rank_p - rank_x == 0 {
                    let sibling = if x == (*p).left { (*p).right } else { (*p).left };
                    let rank_s = self.get_rank(sibling);

                    if rank_p - rank_s == 1 {
                        // Sibling has rank difference 1: simple promotion of parent
                        (*p).rank += 1;
                        x = p; // continue up
                    } else {
                        // Sibling has rank difference 2: rotation is required
                        let _g = (*p).parent;
                        if x == (*p).left {
                            let l = (*x).left;
                            let r = (*x).right;
                            let rank_l = self.get_rank(l);
                            let rank_r = self.get_rank(r);

                            if rank_x - rank_l == 1 {
                                // Single rotation
                                self.rotate_right(p);
                                (*p).rank -= 1;
                            } else if rank_x - rank_r == 1 {
                                // Double rotation
                                self.rotate_left(x);
                                self.rotate_right(p);
                                (*x).rank -= 1;
                                (*p).rank -= 1;
                                (*(*p).parent).rank += 1;
                            }
                        } else {
                            let l = (*x).left;
                            let r = (*x).right;
                            let rank_l = self.get_rank(l);
                            let rank_r = self.get_rank(r);

                            if rank_x - rank_r == 1 {
                                // Single rotation
                                self.rotate_left(p);
                                (*p).rank -= 1;
                            } else if rank_x - rank_l == 1 {
                                // Double rotation
                                self.rotate_right(x);
                                self.rotate_left(p);
                                (*x).rank -= 1;
                                (*p).rank -= 1;
                                (*(*p).parent).rank += 1;
                            }
                        }
                        break; // Balanced!
                    }
                } else {
                    break; // No rank difference violations
                }
            }
        }
    }

    pub fn pop_min(&mut self) -> Option<u64> {
        if self.root.is_null() {
            return None;
        }

        let mut curr = self.root;
        unsafe {
            while !(*curr).left.is_null() {
                curr = (*curr).left;
            }
        }

        let task_id = unsafe { (*curr).task_id };
        let vruntime = unsafe { (*curr).vruntime };
        self.remove(vruntime, task_id);
        Some(task_id)
    }

    pub fn remove(&mut self, vruntime: u64, task_id: u64) {
        let mut curr = self.root;
        while !curr.is_null() {
            unsafe {
                let ord = Self::compare(vruntime, task_id, (*curr).vruntime, (*curr).task_id);
                match ord {
                    Ordering::Less => curr = (*curr).left,
                    Ordering::Greater => curr = (*curr).right,
                    Ordering::Equal => break,
                }
            }
        }

        if curr.is_null() {
            return; // Not found
        }

        unsafe {
            let mut target = curr;
            if !(*curr).left.is_null() && !(*curr).right.is_null() {
                // Node has two children: find successor
                target = (*curr).right;
                while !(*target).left.is_null() {
                    target = (*target).left;
                }
                // Copy successor data to curr
                (*curr).vruntime = (*target).vruntime;
                (*curr).task_id = (*target).task_id;
            }

            // Successor/curr has at most one child
            let child = if !(*target).left.is_null() { (*target).left } else { (*target).right };

            let p = (*target).parent;
            if !child.is_null() {
                (*child).parent = p;
            }

            if p.is_null() {
                self.root = child;
            } else if target == (*p).left {
                (*p).left = child;
            } else {
                (*p).right = child;
            }

            // Deallocate target node
            let _ = alloc::boxed::Box::from_raw(target);

            // Rebalance from parent p
            if !p.is_null() {
                self.delete_rebalance(p);
            }
        }
    }

    fn delete_rebalance(&mut self, mut p: *mut WavlNode) {
        unsafe {
            while !p.is_null() {
                let rank_p = (*p).rank;
                let l = (*p).left;
                let r = (*p).right;
                let rank_l = self.get_rank(l);
                let rank_r = self.get_rank(r);

                // Check 2,2 leaf or rank difference violations
                let is_leaf = l.is_null() && r.is_null();
                if is_leaf && rank_p == 1 {
                    (*p).rank = 0;
                    p = (*p).parent;
                    continue;
                }

                let diff_l = rank_p - rank_l;
                let diff_r = rank_p - rank_r;

                if (diff_l == 2 && diff_r == 2) || (diff_l == 3 && diff_r == 2) || (diff_l == 2 && diff_r == 3) {
                    // Demotion
                    if diff_l == 3 || diff_r == 3 || (diff_l == 2 && diff_r == 2) {
                        (*p).rank -= 1;
                        p = (*p).parent;
                        continue;
                    }
                }

                // If rank difference is 3 on one side, rotation/demotion is needed
                if diff_l == 3 || diff_r == 3 {
                    let (heavy, _light) = if diff_l == 3 { (r, l) } else { (l, r) };
                    let rank_h_l = self.get_rank((*heavy).left);
                    let rank_h_r = self.get_rank((*heavy).right);
                    let diff_h_l = (*heavy).rank - rank_h_l;
                    let diff_h_r = (*heavy).rank - rank_h_r;

                    if diff_h_l == 2 && diff_h_r == 2 {
                        // Sibling is 2,2 node: demote both parent and sibling
                        (*p).rank -= 1;
                        (*heavy).rank -= 1;
                        p = (*p).parent;
                    } else {
                        // Rotation needed
                        if diff_l == 3 {
                            if diff_h_r == 1 {
                                // Single rotation
                                self.rotate_left(p);
                                (*heavy).rank += 1;
                                (*p).rank -= 1;
                                if is_leaf {
                                    (*p).rank -= 1;
                                }
                            } else {
                                // Double rotation
                                self.rotate_right(heavy);
                                self.rotate_left(p);
                                let parent_new = (*p).parent;
                                (*parent_new).rank += 2;
                                (*p).rank -= 2;
                                (*heavy).rank -= 1;
                            }
                        } else {
                            if diff_h_l == 1 {
                                // Single rotation
                                self.rotate_right(p);
                                (*heavy).rank += 1;
                                (*p).rank -= 1;
                                if is_leaf {
                                    (*p).rank -= 1;
                                }
                            } else {
                                // Double rotation
                                self.rotate_left(heavy);
                                self.rotate_right(p);
                                let parent_new = (*p).parent;
                                (*parent_new).rank += 2;
                                (*p).rank -= 2;
                                (*heavy).rank -= 1;
                            }
                        }
                        break; // Balanced!
                    }
                } else {
                    break; // No violations
                }
            }
        }
    }
}

// Clean up entire tree on drop
impl Drop for WavlTree {
    fn drop(&mut self) {
        self.clear_subtree(self.root);
    }
}

impl WavlTree {
    fn clear_subtree(&mut self, node: *mut WavlNode) {
        if !node.is_null() {
            unsafe {
                self.clear_subtree((*node).left);
                self.clear_subtree((*node).right);
                let _ = alloc::boxed::Box::from_raw(node);
            }
        }
    }
}

unsafe impl Send for WavlTree {}
unsafe impl Sync for WavlTree {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wavl_basic_insertion_and_ordering() {
        let mut tree = WavlTree::new();
        tree.insert(100, 1);
        tree.insert(50, 2);
        tree.insert(150, 3);
        tree.insert(75, 4);

        assert_eq!(tree.pop_min(), Some(2)); // vruntime = 50, task_id = 2
        assert_eq!(tree.pop_min(), Some(4)); // vruntime = 75, task_id = 4
        assert_eq!(tree.pop_min(), Some(1)); // vruntime = 100, task_id = 1
        assert_eq!(tree.pop_min(), Some(3)); // vruntime = 150, task_id = 3
        assert_eq!(tree.pop_min(), None);
    }

    #[test]
    fn test_wavl_duplicate_vruntime() {
        let mut tree = WavlTree::new();
        tree.insert(100, 2);
        tree.insert(100, 1);

        assert_eq!(tree.pop_min(), Some(1)); // task_id 1 because of ID sorting
        assert_eq!(tree.pop_min(), Some(2));
        assert_eq!(tree.pop_min(), None);
    }
}
