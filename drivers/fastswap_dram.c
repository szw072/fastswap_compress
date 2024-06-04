#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>//kmap_atomic()
#include <linux/pagemap.h>
#include "fastswap_dram.h"
#include <linux/lzo.h>
#include <linux/crc16.h>
#include <linux/slab.h>//kamlloc()


#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 10) /* must match what server is allocating */

static void *drambuf;

struct zswap_entry {
	struct rb_node rbnode;
	pgoff_t offset;
	int refcount;//用concurrent load时,保护entry不被过早释放
	size_t len;//+++
  u16 crc_uncompress, crc_compress;//++++
};
struct zswap_tree {//包含rb树root
	struct rb_root rbroot;
	spinlock_t lock;
};
static struct zswap_tree *zswap_trees;//rb tree数组,只一个swap area,申请一个


// static atomic_t local_stored_pages = ATOMIC_INIT(0);//未压缩成功存到本地dram数量
static atomic_t zswap_stored_pages = ATOMIC_INIT(0);//存到页面数量

/*********************************
* buf_read functions
**********************************/



/*********************************
* rb tree functions 
**********************************/
static void zswap_rb_erase(struct rb_root *root, struct zswap_entry *entry)
{
	if (!RB_EMPTY_NODE(&entry->rbnode)) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

static int zswap_rb_insert(struct rb_root *root, struct zswap_entry *entry,//如果rb树上发现重复的entry,dupenry指向重复的entry
			struct zswap_entry **dupentry)
{//zswap_entry->offset为tree索引index
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct zswap_entry *myentry;

	while (*link) {
		parent = *link;//entry是带插入rb tree的entry, link是指向rb tree的节点的指针
		myentry = rb_entry(parent, struct zswap_entry, rbnode);//#define rb_entry(ptr, type, member) container_of(ptr, type, member)
		if (myentry->offset > entry->offset)//如果新节点的offset小于父亲节点的offset
			link = &(*link)->rb_left;
		else if (myentry->offset < entry->offset)//如果新节点的offset大于父亲节点的offset
			link = &(*link)->rb_right;
		else {//如果新节点的offset等于父亲节点的offset
			*dupentry = myentry;
			return -EEXIST;
		}
	}
	rb_link_node(&entry->rbnode, parent, link);//插入 把新节点指向其父亲节点
	rb_insert_color(&entry->rbnode, root);//rb树颜色的调整
	return 0;
}

static struct zswap_entry *zswap_rb_search(struct rb_root *root, pgoff_t offset)
{
	struct rb_node *node = root->rb_node;
	struct zswap_entry *entry;

	while (node) {
		entry = rb_entry(node, struct zswap_entry, rbnode);
		if (entry->offset > offset)
			node = node->rb_left;
		else if (entry->offset < offset)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

/* caller must hold the tree lock */
static struct zswap_entry *zswap_entry_find_get(struct rb_root *root,
				pgoff_t offset)//根据offset查entry
{
	struct zswap_entry *entry;

	entry = zswap_rb_search(root, offset);
	// if (entry) 
		// entry->refcount++;//用于设置refcount++

	return entry;
}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
//TODO 使用了refcount 最后也没有使用
// static void zswap_entry_put(struct zswap_tree *tree, 
// 			struct zswap_entry *entry)
// {
// 	// int refcount = --entry->refcount;
// 	// BUG_ON(refcount < 0);
// 	// if (refcount == 0) {
// 	// 	zswap_rb_erase(&tree->rbroot, entry);
// 	// 	zswap_free_entry(entry);
// 	// }
//   zswap_rb_erase(&tree->rbroot, entry);
//   kfree(entry);
// }
//

static void zswap_frontswap_invalidate_area(void)
{
	struct zswap_tree *tree = zswap_trees;
	struct zswap_entry *entry, *n;

	if (!tree)
		return;

	/* walk the tree and free everything */
	spin_lock(&tree->lock);
	rbtree_postorder_for_each_entry_safe(entry, n, &tree->rbroot, rbnode){//先序遍历
    kfree(entry);
    atomic_dec(&zswap_stored_pages);
  }
	tree->rbroot = RB_ROOT;
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees = NULL;
}


void init_rbtree(void){
  struct zswap_tree *tree;//
  // int i;

  tree = kzalloc(sizeof(struct zswap_tree), GFP_KERNEL);//为swap(rb) tree分配空间,包含一个rbroot和lock

  if (!tree) {
    pr_err("alloc failed, zswap disabled for swap type \n");
    BUG();
    return;
  }

  tree->rbroot = RB_ROOT;//为NULL #define RB_ROOT	(struct rb_root) { NULL, }
  spin_lock_init(&tree->lock);
  zswap_trees = tree;
}


int sswap_rdma_write(struct page *page, u64 roffset)
{
	void *src;
  size_t page_len = PAGE_SIZE, wlen;
  void *buf_write, *compress_buf = NULL, *uncompress_buf = NULL;
  u16 crc_uncompress, crc_compress;
  int ret;

  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry = NULL, *dupentry;

  void *wrkmem;

  wrkmem = kmalloc(LZO1X_1_MEM_COMPRESS, GFP_KERNEL);

  src = kmap_atomic(page);
  uncompress_buf = kmalloc(page_len, GFP_KERNEL);//作未压缩page内容的rdma写buf
  if(uncompress_buf == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  compress_buf = kmalloc(2 *  page_len, GFP_KERNEL);//压缩目的地址
  if(compress_buf == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  crc_uncompress = crc16(0x0000, src, page_len);

  //******** 压缩 **************
  ret = lzo1x_1_compress(src, page_len, compress_buf, &wlen, wrkmem);


  if(wlen >= 4096){//不能压缩 使用原page
    crc_compress = crc_uncompress;
    kfree(compress_buf);
    memcpy(uncompress_buf, src, PAGE_SIZE);
    buf_write = uncompress_buf;
    wlen = page_len;
  }
  else{//能压缩 使用压缩后数据
    crc_compress = crc16(0x0000, compress_buf, wlen);
    kfree(uncompress_buf);
    buf_write = compress_buf;
  }
  kunmap_atomic(src);

  //******** 拷贝压缩地址 **************
	// copy_page((void *) (drambuf + roffset), page_vaddr);
  memcpy((void *) (drambuf + roffset), buf_write, wlen);

  // pr_info("[write] cpuid: %d offset: %llx len: %zu --> %zu crc: %hx --> %hx ret: %d", smp_processor_id(), roffset, page_len, wlen, crc_uncompress, crc_compress, ret);


  //******** 插入rb tree **************
  entry = kmalloc(sizeof(struct zswap_entry), GFP_KERNEL); //申请插入rbtree 的swap entry
  if(entry == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }
  RB_CLEAR_NODE(&entry->rbnode);
  entry->offset = roffset;
  entry->len = wlen;
  entry->crc_compress = crc_compress;//+++ 用于compress page读校验
  entry->crc_uncompress = crc_uncompress;//+++ 用于uncompress page读校验

  spin_lock(&tree->lock);
	do {
		ret = zswap_rb_insert(&tree->rbroot, entry, &dupentry);
		if (ret == -EEXIST) {//重复的entry 应该删除重复的entry(dupentry)
      // pr_info("[write_duplicate] offset: %lx", entry->offset);
			// zswap_duplicate_entry++;
			/* remove from rbtree */
			zswap_rb_erase(&tree->rbroot, dupentry);
      kfree(dupentry);//释放entry
			// zswap_entry_put(tree, dupentry)
		}
	} while (ret == -EEXIST);
  spin_unlock(&tree->lock);

  kfree(buf_write);
  kfree(wrkmem);
  return ret;

}
EXPORT_SYMBOL(sswap_rdma_write);

int sswap_rdma_poll_load(int cpu)
{
	return 0;
}
EXPORT_SYMBOL(sswap_rdma_poll_load);

static bool DoDecompress(u64 roffset, size_t len){
  bool ret = false;//默认不解压缩
  size_t page_index;
  page_index = (roffset >> 12);

  if(len < PAGE_SIZE && (page_index % 2 == 0)){//len<PAGE_SIZE && (偶数页 || demand请求)
    ret = true;
  }
  return ret;
}

int sswap_rdma_read_async(struct page *page, u64 roffset)
{
	void *dst;
  void *buf_read;

  struct zswap_tree *tree = zswap_trees;//每个swap area对应一个rb树 这里只使用一个
  struct zswap_entry *entry;

  bool doDecompress, undecompressed;//是否解压缩 和 page状态
  u16 crc_r;
  size_t page_len = PAGE_SIZE, len;
  int ret;

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);//PageLocked(page) page是lock返回1 取反 --> 0 (condition==1 触发BUG())
	VM_BUG_ON_PAGE(PageUptodate(page), page);

  //******** 查rb tree得dlen **************
	spin_lock(&tree->lock);//lock 防止数据读写冲突
	entry = zswap_entry_find_get(&tree->rbroot, roffset);//1.根据roffset在rb树上查找到entry 包含len 2.refcount++
  if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
    pr_info("rb treee not found roffset: %llx", roffset);
    BUG();
		return -1;
	}
	spin_unlock(&tree->lock);//unlock
  // pr_info("found rbtree entry roffest: %lx, length: %d --> %zu crc: %hx --> %hx", entry->offset, 4096, entry->len, entry->crc_uncompress, entry->crc_compress);

	dst = kmap_atomic(page);
  buf_read = kmalloc(PAGE_SIZE, GFP_KERNEL);//作为read buf
  if(buf_read == NULL){
    pr_err("kmalloc wrong!!!");
    BUG();
  }

  memcpy(buf_read, (void *) (drambuf + roffset), entry->len);
 

  //******** 读校验 **************
  crc_r = crc16(0x0000 ,buf_read, entry->len);
  undecompressed = entry->len < page_len ? true : false;//此时page状态
  if(undecompressed){//page待解压缩
    if(entry->crc_compress != crc_r){
      pr_err("[!!!] compress crc wrong!!! cpuid: %d offset: %llx crc write: %hx read: %hx",smp_processor_id(), roffset, entry->crc_compress, crc_r);
      BUG();
    }
  }
  else{//page无需解压缩
    if(entry->crc_uncompress != crc_r){
      pr_err("[!!!] uncompress crc wrong!!! cpuid: %d offset: %llx crc write: %hx read: %hx",smp_processor_id(), roffset, entry->crc_uncompress, crc_r);
      BUG();
    }
  }

  //******** 解压缩(含判断) **************
  // 存在当 page len < 4KB 且 奇数index页 不解压缩 需要在kernel进一步解压缩
  doDecompress = DoDecompress(roffset, entry->len); //根据roffset最后一位奇偶和len判断 
  // doDecompress = entry->len < page_len ? true : false;//根据len判断是否解压缩

  if(doDecompress){//解压缩
    ret = lzo1x_decompress_safe(buf_read, entry->len, dst, &page_len); 
    if(ret != 0){
      pr_err("[done back] decompress wrong!!! ret: %d", ret);
      BUG();
    }
    undecompressed = false;//更新page状态
    len = page_len;//更新page长度
  }
  else{//不解压缩 --> 1)PageSize=4096 2)PageSize < 4096 index奇数页 && page非demand请求 (在内核解压缩)
    memcpy(dst, buf_read, entry->len);
    len = entry->len;
  } 
  page->len = len;//更新处理完成后page长度 用于在kernel进一步做解压缩 [include/linux/mm_types.h]
  page->undecompressed = undecompressed;


	kunmap_atomic(dst);
  kfree(buf_read);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}
EXPORT_SYMBOL(sswap_rdma_read_async);

int sswap_rdma_read_sync(struct page *page, u64 roffset)
{
	return sswap_rdma_read_async(page, roffset);
}
EXPORT_SYMBOL(sswap_rdma_read_sync);

int sswap_rdma_drain_loads_sync(int cpu, int target)
{
	return 1;
}
EXPORT_SYMBOL(sswap_rdma_drain_loads_sync);

static void __exit sswap_dram_cleanup_module(void)
{
	vfree(drambuf);
	zswap_frontswap_invalidate_area();
}

static int __init sswap_dram_init_module(void)
{
	pr_info("start: %s\n", __FUNCTION__);
	pr_info("will use new DRAM backend");

	drambuf = vzalloc(REMOTE_BUF_SIZE);
	pr_info("vzalloc'ed %lu bytes for dram backend\n", REMOTE_BUF_SIZE);

	pr_info("DRAM backend is ready for reqs\n");

	init_rbtree();

	return 0;
}

module_init(sswap_dram_init_module);
module_exit(sswap_dram_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DRAM backend");
